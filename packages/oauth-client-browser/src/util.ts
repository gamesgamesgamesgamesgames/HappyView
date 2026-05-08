const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

export function buildLoopbackClientId(
  location: { hostname: string; pathname: string; port: string },
  localhost = "127.0.0.1",
): string {
  if (!LOOPBACK_HOSTS.has(location.hostname)) {
    throw new TypeError(
      `Expected a loopback hostname, got "${location.hostname}"`,
    );
  }

  const host =
    localhost.includes(":") && !localhost.startsWith("[")
      ? `[${localhost}]`
      : localhost;
  const port = location.port ? `:${location.port}` : "";
  const redirectUri = `http://${host}${port}${location.pathname}`;

  const pathname = location.pathname === "/" ? "" : location.pathname;
  const encodedRedirect = encodeURIComponent(redirectUri);
  return `http://localhost${pathname}?redirect_uri=${encodedRedirect}`;
}
