import { Webhook } from "svix";
import { headers } from "next/headers";

export async function POST(req) {
  const SIGNING_SECRET = process.env.SIGNING_SECRET;

  if (!SIGNING_SECRET) {
    throw new Error(
      "Error: Please add SIGNING_SECRET from Clerk Dashboard to .env or .env.local"
    );
  }

  const wh = new Webhook(SIGNING_SECRET);

  const headerPayload = await headers();
  const svix_id = headerPayload.get("svix-id");
  const svix_timestamp = headerPayload.get("svix-timestamp");
  const svix_signature = headerPayload.get("svix-signature");

  if (!svix_id || !svix_timestamp || !svix_signature) {
    return new Response("Error: Missing Svix headers", {
      status: 400,
    });
  }

  const payload = await req.json();
  const body = JSON.stringify(payload);

  let evt;

  try {
    evt = wh.verify(body, {
      "svix-id": svix_id,
      "svix-timestamp": svix_timestamp,
      "svix-signature": svix_signature,
    });
  } catch (err) {
    console.error("Error: Could not verify webhook:", err);
    return new Response("Error: Verification error", {
      status: 400,
    });
  }

  const { id } = evt.data;
  const eventType = evt.type;
  console.log(`Received webhook with ID ${id} and event type of ${eventType}`);
  console.log("Webhook payload:", body);

  if (eventType === "user.created") {
    const { id, email_addresses, first_name, last_name } = evt.data;
    console.log(`User created: ${id}`);
    console.log(`Email addresses: ${email_addresses}`);
    console.log(`First name: ${first_name}`);
    console.log(`Last name: ${last_name}`);
  }

  if (eventType === "user.updated") {
    const { id, email_addresses, first_name, last_name } = evt.data;
    console.log(`User updated: ${id}`);
    console.log(`Email addresses: ${email_addresses}`);
    console.log(`First name: ${first_name}`);
    console.log(`Last name: ${last_name}`);
  }

  if (eventType === "user.deleted") {
    const { id } = evt.data;
    console.log(`User deleted: ${id}`);
  }

  return new Response("Webhook received", { status: 200 });
}
