export async function onRequest(context) {
  const password = context.env.SITE_PASSWORD;

  if (!password) {
    return new Response("Access unavailable.", {
      status: 503,
      headers: { "Cache-Control": "no-store" }
    });
  }

  const auth = context.request.headers.get("Authorization");
  let authorized = false;

  if (auth && auth.startsWith("Basic ")) {
    try {
      const credentials = atob(auth.slice(6));
      const separator = credentials.indexOf(":");

      if (separator >= 0) {
        const username = credentials.slice(0, separator);
        const supplied = credentials.slice(separator + 1);

        authorized =
          username === "practitioner" &&
          supplied === password;
      }
    } catch {
      authorized = false;
    }
  }

  if (!authorized) {
    return new Response("Practitioner Headquarters - Restricted Access", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="Practitioner Headquarters"',
        "Cache-Control": "no-store"
      }
    });
  }

  const response = await context.next();
  const secured = new Response(response.body, response);
  secured.headers.set("Cache-Control", "private, no-store");
  return secured;
}
