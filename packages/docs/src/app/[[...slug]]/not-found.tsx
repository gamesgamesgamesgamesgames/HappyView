import { DocsBody, DocsPage } from 'fumadocs-ui/layouts/docs/page';

export default function NotFound() {
  return (
    <DocsPage>
      <DocsBody>
        <h1>404 — Page Not Found</h1>
        <p>The page you're looking for doesn't exist.</p>
      </DocsBody>
    </DocsPage>
  );
}
