import { visit } from 'unist-util-visit';
import type { Root } from 'mdast';

export function remarkStripMdExtension() {
  return (tree: Root) => {
    visit(tree, 'link', (node) => {
      if (node.url && !node.url.startsWith('http')) {
        node.url = node.url.replace(/\.md(#|$)/, '$1');
      }
    });
  };
}
