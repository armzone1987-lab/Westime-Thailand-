import { createClient } from "https://esm.sh/@supabase/supabase-js@2.112.4";

// Westime staff-only read API. Never send service credentials or customer data to public pages.
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Content-Type": "application/json; charset=utf-8",
};
const cols = [
  "id", "warranty_id", "order_id", "status", "brand", "model", "color",
  "external_sku", "sales_channel", "purchase_date", "warranty_expires_on",
  "activated_at", "registered_at", "customer_name", "customer_phone",
  "customer_email", "registration_source", "replaced_by_warranty_id", "created_at",
].join(",");
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const statuses = new Set(["active", "expired", "claimed", "replaced"]);

function respond(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: cors });
}

async function limitedJson(req: Request) {
  const reader = req.body?.getReader();
  if (!reader) throw new Error("EMPTY_BODY");
  let bytes = 0;
  const chunks: Uint8Array[] = [];
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    bytes += value.length;
    if (bytes > 4096) {
      await reader.cancel();
      throw new Error("BODY_TOO_LARGE");
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) { buf.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(new TextDecoder().decode(buf));
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (req.method !== "POST") return respond({ ok: false, message: "METHOD_NOT_ALLOWED" }, 405);

  const header = req.headers.get("authorization") || "";
  if (!/^Bearer\s+\S+$/i.test(header)) {
    return respond({ ok: false, message: "กรุณาเข้าสู่ระบบเจ้าหน้าที่" }, 401);
  }
  const token = header.replace(/^Bearer\s+/i, "");
  const url = Deno.env.get("SUPABASE_URL");
  const secret = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !secret) return respond({ ok: false, message: "ระบบยังไม่พร้อมให้บริการ" }, 503);
  const db = createClient(url, secret, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  // Verify the real Supabase user server-side: client-supplied claims are never trusted.
  const { data: authData, error: authError } = await db.auth.getUser(token);
  if (authError || !authData.user) {
    return respond({ ok: false, message: "เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่" }, 401);
  }

  const { data: admin, error: accessError } = await db.from("admin_users")
    .select("role,active").eq("user_id", authData.user.id).maybeSingle();
  if (accessError) return respond({ ok: false, message: "ตรวจสอบสิทธิ์ไม่สำเร็จ" }, 503);
  // Personal data and export access are intentionally restricted to active admins only.
  if (!admin?.active || admin.role !== "admin") {
    return respond({ ok: false, message: "บัญชีนี้ไม่มีสิทธิ์ดูทะเบียนข้อมูลลูกค้า" }, 403);
  }

  let body: Record<string, unknown>;
  try {
    const parsed = await limitedJson(req);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("BAD_BODY");
    body = parsed as Record<string, unknown>;
  } catch {
    return respond({ ok: false, message: "รูปแบบข้อมูลไม่ถูกต้อง" }, 400);
  }

  try {
    if (body.action === "list") {
      const page = Number(body.page ?? 1);
      const size = Number(body.pageSize ?? 25);
      if (!Number.isInteger(page) || page < 1 || page > 1000 ||
          !Number.isInteger(size) || size < 1 || size > 100) {
        return respond({ ok: false, message: "ช่วงข้อมูลไม่ถูกต้อง" }, 400);
      }
      const status = String(body.status ?? "").trim();
      if (status && !statuses.has(status)) {
        return respond({ ok: false, message: "สถานะไม่ถูกต้อง" }, 400);
      }
      const rawSearch = String(body.search ?? "").trim();
      if (rawSearch.length > 80) return respond({ ok: false, message: "คำค้นยาวเกินไป" }, 400);
      // Keep PostgREST .or filter syntax separate from user-controlled characters.
      const search = rawSearch.replace(/[^\p{L}\p{M}\p{N}\s_-]/gu, "").trim();
      let query = db.from("warranty_units").select(cols, { count: "exact" })
        .in("status", ["active", "expired", "claimed", "replaced"]);
      if (status) query = query.eq("status", status);
      if (search) {
        const s = "%" + search + "%";
        query = query.or([
          "warranty_id.ilike." + s, "order_id.ilike." + s,
          "model.ilike." + s, "external_sku.ilike." + s,
          "customer_name.ilike." + s, "customer_phone.ilike." + s,
          "customer_email.ilike." + s,
        ].join(","));
      }
      const start = (page - 1) * size;
      const { data, count, error } = await query.order("created_at", { ascending: false })
        .order("id", { ascending: true }).range(start, start + size - 1);
      if (error) {
        console.error("registry list", error.code);
        return respond({ ok: false, message: "ไม่สามารถโหลดทะเบียนได้" }, 503);
      }
      return respond({ ok: true, rows: data ?? [], total: count ?? 0, page, pageSize: size });
    }
    if (body.action === "history") {
      const id = String(body.id ?? "");
      if (!uuid.test(id)) return respond({ ok: false, message: "รหัสข้อมูลไม่ถูกต้อง" }, 400);
      const { data: unit, error: unitError } = await db.from("warranty_units")
        .select("id").eq("id", id).in("status", ["active", "expired", "claimed", "replaced"]).maybeSingle();
      if (unitError) return respond({ ok: false, message: "โหลดประวัติไม่สำเร็จ" }, 503);
      if (!unit) return respond({ ok: false, message: "ไม่พบข้อมูลรับประกัน" }, 404);
      const { data, error } = await db.from("warranty_events")
        .select("event_type,note,created_at").eq("warranty_unit_id", id)
        .order("created_at", { ascending: false }).limit(100);
      if (error) {
        console.error("registry history", error.code);
        return respond({ ok: false, message: "โหลดประวัติไม่สำเร็จ" }, 503);
      }
      return respond({ ok: true, events: data ?? [] });
    }
    return respond({ ok: false, message: "คำสั่งไม่ถูกต้อง" }, 400);
  } catch (error) {
    console.error("registry unexpected", error instanceof Error ? error.name : "unknown");
    return respond({ ok: false, message: "ระบบยังไม่พร้อมให้บริการ" }, 503);
  }
});
