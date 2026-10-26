"""Self-contained static site smoke checks, no third-party tools required."""
from html.parser import HTMLParser
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
class Document(HTMLParser):
    def __init__(self): super().__init__(); self.ids=set(); self.links=[]; self.images=[]
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if 'id' in attrs: assert attrs['id'] not in self.ids, f"Duplicate id {attrs['id']}"; self.ids.add(attrs['id'])
        if tag=='a' and attrs.get('href'): self.links.append(attrs['href'])
        if tag=='img' and not attrs.get('alt'): self.images.append(tag)
html=(ROOT/'index.html').read_text(encoding='utf-8')
parser=Document();parser.feed(html)
assert not parser.images, 'Image without alt text'
for link in parser.links:
    if link.startswith('#'): assert link[1:] in parser.ids, f'Broken anchor {link}'
    if link.startswith('resume.html'): assert (ROOT/link).exists(), f'Missing CV page {link}'
    if link.startswith('assets/'): assert (ROOT/link).exists(), f'Missing local asset {link}'
assert '<title>' in html
assert len(re.findall(r'data-category=', html)) == 4
assert (ROOT/'app.js').exists()
assert (ROOT/'styles.css').exists()
print(f'SITE PASS: {len(parser.ids)} unique anchors, {len(parser.links)} links, 4 projects, local resume')
