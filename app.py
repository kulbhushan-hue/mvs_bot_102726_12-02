from __future__ import annotations
import io, re, time, json, hashlib, urllib.parse, urllib.robotparser
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests
import streamlit as st
from bs4 import BeautifulSoup

try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / 'data'
DATA_DIR.mkdir(exist_ok=True)
ZOS_VERSIONS = ['2.5', '3.1', '3.2']
ZOS_ALIASES = {
    '2.5': ['z/os v2r5', 'z/os 2.5', 'zos 2.5', 'v2r5'],
    '3.1': ['z/os v3r1', 'z/os 3.1', 'zos 3.1', 'v3r1'],
    '3.2': ['z/os v3r2', 'z/os 3.2', 'zos 3.2', 'v3r2'],
}
PTF_RE = re.compile(r'\b(?:U[JNST]\d{5,7}|[A-Z]{2,3}\d{4,7}|LU\d{5,7}|PTF\s+[A-Z0-9]{5,10})\b', re.I)
APAR_RE = re.compile(r'\b(?:OA|PH|PI|PQ|PK|PM|PE|SA|SI|SW|II|BC|QF|TS|LU)\d{5,7}\b', re.I)
DEFAULT_REGISTRY = {
    'IBM': ['https://www.ibm.com/docs/en/zos', 'https://www.ibm.com/support/fixcentral/'],
    'Broadcom': ['https://ftpdocs.broadcom.com/WebInterface/phpdocs/0/MSPSaccount/COMPAT/zos_compat.HTML'],
    'BMC': ['https://www.bmc.com/support/resources/os390-and-zos-compatibilty.html', 'https://www.bmc.com/support/resources/day-one-support.html'],
    'Rocket Software / ASG': ['https://www.rocketsoftware.com/', 'https://community.rocketsoftware.com/product-updates'],
    'OpenText / Micro Focus': ['https://www.opentext.com/', 'https://docs.microfocus.com/'],
    'Precisely': ['https://www.precisely.com/'],
    'UNICOM': ['https://www.unicomglobal.com/'],
    'Other / discovered vendor': [],
}
USER_AGENT = 'MVS-BOT-Research/1.0 (+respectful, page-limited compatibility research)'

st.set_page_config(page_title='MVS BOT | Compatibility & PTF Analyzer', page_icon='🖥️', layout='wide')
st.markdown('''<style>
.main {background:#f5f8fc}.block-container{padding-top:1.2rem;max-width:1600px}
[data-testid="stSidebar"]{background:#0b1f38}
[data-testid="stSidebar"] *{color:#f5f8ff}
div[data-testid="stMetric"]{background:white;border:1px solid #dce6f2;padding:14px;border-radius:10px}
</style>''', unsafe_allow_html=True)

@st.cache_data(ttl=1800, show_spinner=False)
def fetch_page(url: str):
    headers = {'User-Agent': USER_AGENT}
    response = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
    response.raise_for_status()
    ctype = response.headers.get('Content-Type', '').lower()
    if 'pdf' in ctype or response.url.lower().endswith('.pdf'):
        if PdfReader is None:
            raise RuntimeError('PDF found. Install pypdf to extract PDF text.')
        reader = PdfReader(io.BytesIO(response.content))
        text = ' '.join((page.extract_text() or '') for page in reader.pages[:60])
        return re.sub(r'\s+', ' ', text), [], response.url.split('/')[-1] or 'PDF document', response.url
    soup = BeautifulSoup(response.text, 'html.parser')
    title = soup.title.get_text(' ', strip=True) if soup.title else response.url
    for node in soup(['script', 'style', 'noscript', 'svg', 'nav', 'footer']):
        node.decompose()
    text = re.sub(r'\s+', ' ', soup.get_text(' ', strip=True))
    links = []
    base_host = urllib.parse.urlparse(response.url).netloc.lower()
    for a in soup.find_all('a', href=True):
        href = urllib.parse.urljoin(response.url, a['href'].strip())
        parsed = urllib.parse.urlparse(href)
        if parsed.scheme in ('http', 'https') and parsed.netloc.lower() == base_host:
            label = a.get_text(' ', strip=True)[:180]
            if not any(x in parsed.path.lower() for x in ['logout', 'signout', 'javascript:']):
                links.append((label, href.split('#')[0]))
    return text, links, title, response.url

def robots_allowed(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    robots_url = f'{parsed.scheme}://{parsed.netloc}/robots.txt'
    rp = urllib.robotparser.RobotFileParser()
    try:
        rp.set_url(robots_url); rp.read()
        return rp.can_fetch(USER_AGENT, url)
    except Exception:
        # If robots.txt cannot be retrieved, do not treat that as blanket permission.
        return False

def context_for(text: str, aliases: list[str], radius: int = 350) -> str:
    low = text.lower()
    for alias in aliases:
        idx = low.find(alias.lower())
        if idx >= 0:
            return text[max(0, idx-radius):min(len(text), idx+radius)]
    return ''

def classify_context(context: str) -> str:
    if not context:
        return 'Unknown'
    s = context.lower()
    negative = re.search(r'\b(not supported|unsupported|not compatible|incompatible|no support|not available)\b', s)
    positive = re.search(r'\b(supported|compatible|certified|yes)\b', s)
    conditional = re.search(r'\b(conditional|with ptf|requires ptf|requires maintenance|planned|under review|tbd|to be determined)\b', s)
    if negative: return 'No (review evidence)'
    if conditional: return 'Conditional / Review'
    if positive: return 'Potential Yes — verify'
    return 'Unknown'

def page_evidence(url: str, product: str, release: str):
    text, links, title, final_url = fetch_page(url)
    terms = [x.strip() for x in [product, release] if x and x.strip()]
    relevant = (not terms) or all(term.lower() in text.lower() for term in terms) or any(term.lower() in text.lower() for term in terms)
    ptfs = sorted(set(x.upper().replace('PTF ', '') for x in PTF_RE.findall(text)))
    apars = sorted(set(x.upper() for x in APAR_RE.findall(text)))
    # Keep direct anchor URLs for maintenance identifiers (especially Broadcom matrix cells).
    ptf_link_map, apar_link_map, related_links = {}, {}, []
    for label, href in links:
        combined = f'{label} {href}'
        for ident in set(x.upper().replace('PTF ', '') for x in PTF_RE.findall(combined)):
            ptf_link_map.setdefault(ident, set()).add(href)
        for ident in set(x.upper() for x in APAR_RE.findall(combined)):
            apar_link_map.setdefault(ident, set()).add(href)
        if re.search(r'ptf|apar|fixcat|maintenance|holddata|service|compat|download|fix.?central', combined, re.I):
            related_links.append(f'{label or "Maintenance link"}: {href}')
    statuses, excerpts = {}, {}
    for version, aliases in ZOS_ALIASES.items():
        snippet = context_for(text, aliases)
        statuses['z/OS ' + version] = classify_context(snippet)
        excerpts['Evidence ' + version] = snippet[:700]
    digest = hashlib.sha256(text.encode('utf-8', errors='ignore')).hexdigest()[:16]
    ptf_links = '; '.join(sorted({url for urls in ptf_link_map.values() for url in urls}))
    apar_links = '; '.join(sorted({url for urls in apar_link_map.values() for url in urls}))
    return {'Page title': title, 'URL': final_url, 'Relevant': 'Yes' if relevant else 'Review',
            'PTF candidates': ', '.join(ptfs) if ptfs else 'None extracted',
            'APAR candidates': ', '.join(apars) if apars else 'None extracted',
            'PTF-specific links': ptf_links or 'No direct PTF link found on this page',
            'APAR-specific links': apar_links or 'No direct APAR link found on this page',
            'Related maintenance links': '; '.join(related_links) or 'No related maintenance links found',
            'Text excerpt': text[:1200], 'Content hash': digest, **statuses, **excerpts}, links

def crawl(seeds: list[str], product: str, release: str, max_pages: int, delay: float = 0.5):
    queue = deque((u, 0) for u in seeds if u.startswith(('http://','https://')))
    seen, records = set(), []
    while queue and len(seen) < max_pages:
        url, depth = queue.popleft()
        url = url.split('#')[0]
        if url in seen: continue
        seen.add(url)
        if not robots_allowed(url):
            records.append({'Page title':'Skipped by robots policy or robots.txt unavailable','URL':url,'Relevant':'No','PTF candidates':'Not checked','APAR candidates':'Not checked','Text excerpt':'URL was not fetched because robots permission could not be confirmed.','Content hash':'',**{'z/OS '+v:'Unknown' for v in ZOS_VERSIONS}})
            continue
        try:
            rec, links = page_evidence(url, product, release)
            records.append(rec)
            if depth < 2:
                scored = []
                for label, link in links:
                    if link in seen: continue
                    score = sum(word in (label+' '+link).lower() for word in ['compat','ptf','apar','release','maintenance','support','product','zos','fix','install','program temporary fix'])
                    if score: scored.append((score, label, link))
                for _, _, link in sorted(scored, reverse=True)[:max_pages]:
                    if len(queue) < max_pages * 4: queue.append((link, depth+1))
        except Exception as exc:
            records.append({'Page title':'Fetch error / inaccessible','URL':url,'Relevant':'Unknown','PTF candidates':'Unknown','APAR candidates':'Unknown','Text excerpt':str(exc)[:500],'Content hash':'',**{'z/OS '+v:'Unknown' for v in ZOS_VERSIONS}})
        time.sleep(delay)
    return records, list(seen)

def workbook_bytes(compat: pd.DataFrame, evidence: pd.DataFrame, input_df: pd.DataFrame | None = None, preserved_sheets: dict[str, pd.DataFrame] | None = None) -> bytes:
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        compat.to_excel(writer, index=False, sheet_name='Compatibility')
        evidence.to_excel(writer, index=False, sheet_name='Source Evidence')
        if input_df is not None: input_df.to_excel(writer, index=False, sheet_name='Input Inventory')
        # Preserve every sheet from an imported assessment workbook in the exported report.
        if preserved_sheets:
            for original_name, frame in preserved_sheets.items():
                safe_name = str(original_name)[:31] or 'Imported Sheet'
                if safe_name in writer.book.sheetnames:
                    safe_name = ('Source ' + safe_name)[:31]
                frame.to_excel(writer, index=False, sheet_name=safe_name)
        review = compat[compat.get('Compatible', pd.Series(dtype=str)).astype(str).str.contains('Unknown|Review|Conditional', case=False, na=True)] if not compat.empty else pd.DataFrame()
        review.to_excel(writer, index=False, sheet_name='Manual Review')
        for ws in writer.book.worksheets:
            ws.freeze_panes = 'A2'; ws.auto_filter.ref = ws.dimensions
            for col in ws.columns:
                max_len = min(60, max(12, max((len(str(c.value or '')) for c in list(col)[:200]), default=12) + 2))
                ws.column_dimensions[col[0].column_letter].width = max_len
                # Turn exact URL cells into clickable hyperlinks in the exported workbook.
                for cell in list(col)[1:]:
                    value = str(cell.value or '').strip()
                    if value.startswith(('https://', 'http://')) and '\n' not in value and ';' not in value:
                        cell.hyperlink = value
                        cell.style = 'Hyperlink'
    return buffer.getvalue()

def load_seed_data():
    frames=[]
    for filename in ['asg_compat.csv','bmc_compat.csv','broadcom_compat.csv']:
        p = APP_DIR / 'data' / filename
        if p.exists():
            try:
                d = pd.read_csv(p); d['Seed file'] = filename; frames.append(d)
            except Exception: pass
    return pd.concat(frames, ignore_index=True, sort=False) if frames else pd.DataFrame()

st.title('🖥️ MVS BOT')
st.caption('Mainframe Software Compatibility & PTF Analyzer • all-vendor source registry • z/OS 2.5 / 3.1 / 3.2')
st.warning('Research tool, not installation approval. Extracted PTFs are candidates until verified against the exact product release, vendor instructions, SMP/E HOLDDATA and applicable FIXCAT requirements.')

if 'registry' not in st.session_state:
    st.session_state.registry = {k:list(v) for k,v in DEFAULT_REGISTRY.items()}
if 'history' not in st.session_state: st.session_state.history = []
if 'evidence' not in st.session_state: st.session_state.evidence = pd.DataFrame()
if 'compatibility' not in st.session_state: st.session_state.compatibility = pd.DataFrame()
if 'assessment_sheets' not in st.session_state: st.session_state.assessment_sheets = {}
if 'assessment_source_name' not in st.session_state: st.session_state.assessment_source_name = ''
if 'assessment_inventory' not in st.session_state: st.session_state.assessment_inventory = pd.DataFrame()

lookup_tab, upload_tab, registry_tab, history_tab, reports_tab = st.tabs(['🔎 Product Lookup','📤 Excel Bulk Upload','🏢 Vendor Registry','🕘 Research History','📊 Reports'])
with lookup_tab:
    st.subheader('Investigate a product')
    c1,c2,c3=st.columns([1,2,1])
    with c1: vendor = st.selectbox('Vendor', list(st.session_state.registry.keys()) + ['Add vendor / other'])
    with c2: product = st.text_input('Product name', placeholder='e.g. Db2, MainView, CA 7, TMON')
    with c3: release = st.text_input('Product release / VRM', placeholder='Exact release recommended')
    targets = st.multiselect('Target z/OS versions', ZOS_VERSIONS, default=ZOS_VERSIONS)
    default_urls = st.session_state.registry.get(vendor, [])
    source_text = st.text_area('Official documentation seed URLs (one per line)', '\n'.join(default_urls), height=100, help='Add official product compatibility, release notes, PTF, APAR, installation and support pages. Crawler follows same-domain links only.')
    col1,col2=st.columns([1,3])
    with col1: max_pages = st.slider('Page limit', 1, 50, 10, help='Maximum URL attempts, not a guarantee of ten successful reads.')
    with col2: st.caption('The crawler checks robots.txt before fetching and skips URLs when permission cannot be confirmed. Login-protected pages are not bypassed.')
    if st.button('Start compatibility research', type='primary', use_container_width=True):
        if not product.strip(): st.error('Enter a product name.')
        elif not source_text.strip(): st.error('Add at least one official documentation URL for this vendor.')
        else:
            seeds=[x.strip() for x in source_text.splitlines() if x.strip().startswith(('http://','https://'))]
            with st.spinner(f'Checking up to {max_pages} URLs for {product}…'):
                records, visited = crawl(seeds, product.strip(), release.strip(), max_pages)
            ev = pd.DataFrame(records)
            st.session_state.evidence = ev
            rows=[]
            for version in targets:
                column='z/OS '+version
                matched = ev[ev.get('Relevant', pd.Series(index=ev.index,dtype=str)).eq('Yes')] if not ev.empty else ev
                statuses = matched[column].astype(str).tolist() if not matched.empty and column in matched else []
                if any(s.startswith('No') for s in statuses): result='No — evidence requires review'
                elif any(s.startswith('Conditional') for s in statuses): result='Conditional / Review'
                elif any(s.startswith('Potential Yes') for s in statuses): result='Potential Yes — verify'
                else: result='Unknown'
                ptfs = sorted(set(x.strip() for val in (matched.get('PTF candidates', []) if not matched.empty else []) for x in str(val).split(',') if x.strip() and x.strip()!='None extracted'))
                apars = sorted(set(x.strip() for val in (matched.get('APAR candidates', []) if not matched.empty else []) for x in str(val).split(',') if x.strip() and x.strip()!='None extracted'))
                urls = matched['URL'].dropna().astype(str).tolist() if not matched.empty and 'URL' in matched else []
                rows.append({'Vendor':vendor,'Product':product.strip(),'Release':release.strip(),'z/OS version':version,'Compatible':result,'PTFs (candidates)':'; '.join(ptfs) if ptfs else 'Not found','PTF links (exact)':'\n'.join(x for x in matched.get('PTF-specific links', pd.Series(dtype=str)).astype(str) if x and not x.startswith('No direct')) or 'No direct PTF URL found','APARs (candidates)':'; '.join(apars) if apars else 'Not found','APAR links (exact)':'\n'.join(x for x in matched.get('APAR-specific links', pd.Series(dtype=str)).astype(str) if x and not x.startswith('No direct')) or 'No direct APAR URL found','Evidence URL(s)':'\n'.join(urls),'Evidence status':'Needs human verification','Pages attempted':len(visited),'Checked UTC':datetime.now(timezone.utc).isoformat()})
            comp=pd.DataFrame(rows); st.session_state.compatibility=comp
            st.session_state.history.append({'Vendor':vendor,'Product':product.strip(),'Release':release.strip(),'Pages attempted':len(visited),'Records':len(ev),'Checked UTC':datetime.now(timezone.utc).isoformat()})
            st.success(f'Investigation finished: {len(visited)} URL attempts, {len(ev)} evidence records. Results are provisional.')
    if not st.session_state.compatibility.empty:
        st.subheader('Compatibility results')
        st.dataframe(st.session_state.compatibility, use_container_width=True, hide_index=True, column_config={'PTF links (exact)':st.column_config.LinkColumn('PTF detail URL'),'APAR links (exact)':st.column_config.LinkColumn('APAR detail URL'),'Evidence URL(s)':st.column_config.TextColumn('Evidence URLs')})
        if not st.session_state.evidence.empty:
            st.subheader('Evidence pages actually attempted')
            st.dataframe(st.session_state.evidence, use_container_width=True, hide_index=True, column_config={'URL':st.column_config.LinkColumn('Source URL')})

with upload_tab:
    st.subheader('Bulk inventory: research every product in the workbook')
    st.write('Upload the ISV assessment workbook or another inventory. MVS BOT detects product-bearing sheets, consolidates all product rows, then attempts vendor-page research for each product. It does not silently treat an unsearched product as compatible.')
    uploaded=st.file_uploader('Choose inventory or assessment file', type=['xlsx','xls','csv'], key='inventory')
    if uploaded:
        try:
            if uploaded.name.lower().endswith('.csv'):
                sheets={'Inventory':pd.read_csv(uploaded)}
            else:
                sheets=pd.read_excel(uploaded, sheet_name=None)
                st.session_state.assessment_sheets={str(k):v.copy() for k,v in sheets.items()}
                st.session_state.assessment_source_name=uploaded.name
            st.write(f'{len(sheets)} sheet(s) read: '+', '.join(f'{name} ({len(frame)} rows)' for name,frame in sheets.items()))

            def norm_header(value):
                return re.sub(r'[^a-z0-9]+',' ',str(value).strip().lower()).strip()
            def find_column(frame, aliases):
                by_norm={norm_header(c):c for c in frame.columns}
                for alias in aliases:
                    if norm_header(alias) in by_norm: return by_norm[norm_header(alias)]
                # allow safe partial matching for vendor-maintained column variants
                for alias in aliases:
                    a=norm_header(alias)
                    for key,col in by_norm.items():
                        if a and (a in key or key in a): return col
                return None
            product_aliases=['product','product name','software','product title','application']
            vendor_aliases=['vendor','manufacturer','publisher','company']
            release_aliases=['vrm','version','release','product version','product release']
            url_aliases=['link to verify compatibility report','link to verify compatibility','evidence url','source url','url','comments link','documentation link']
            compat_aliases=['r3 2 compatible y yes or n no','r3 2 compatible','z os 3 2 compatible','zos 3 2 compatible','compatible']
            ptf_aliases=['if yes ptf required','ptf required','required ptf','ptf']
            message_aliases=['message id to identify product version','messsage id to identify product version','message id','fixcat']
            all_rows=[]; sheet_map=[]
            for sheet_name,frame in sheets.items():
                if frame is None or frame.empty: continue
                pcol=find_column(frame,product_aliases)
                vcol=find_column(frame,vendor_aliases)
                rcol=find_column(frame,release_aliases)
                ucol=find_column(frame,url_aliases)
                ccol=find_column(frame,compat_aliases)
                tcol=find_column(frame,ptf_aliases)
                mcol=find_column(frame,message_aliases)
                # A vendor directory sheet without product values is retained, but not treated as inventory.
                if pcol is None:
                    sheet_map.append({'Sheet':sheet_name,'Rows':len(frame),'Product column':'Not found','Action':'Preserved as source sheet; not treated as product inventory'})
                    continue
                count=0
                for row_idx, row in frame.iterrows():
                    product_val=row.get(pcol)
                    if pd.isna(product_val) or not str(product_val).strip(): continue
                    item={'Source sheet':sheet_name,'Source row':int(row_idx)+2,'Vendor':str(row.get(vcol,'')).strip() if vcol and pd.notna(row.get(vcol,'')) else '',
                          'Product':str(product_val).strip(),'Release':str(row.get(rcol,'')).strip() if rcol and pd.notna(row.get(rcol,'')) else '',
                          'Source compatibility':str(row.get(ccol,'')).strip() if ccol and pd.notna(row.get(ccol,'')) else '',
                          'Source PTF':str(row.get(tcol,'')).strip() if tcol and pd.notna(row.get(tcol,'')) else '',
                          'Source URL':str(row.get(ucol,'')).strip() if ucol and pd.notna(row.get(ucol,'')) else '',
                          'Message ID / FIXCAT':str(row.get(mcol,'')).strip() if mcol and pd.notna(row.get(mcol,'')) else ''}
                    all_rows.append(item); count+=1
                sheet_map.append({'Sheet':sheet_name,'Rows':len(frame),'Product column':str(pcol),'Product rows detected':count,'Action':'Included in research inventory'})
            inventory=pd.DataFrame(all_rows)
            st.subheader('Detected sheet and column mapping')
            st.dataframe(pd.DataFrame(sheet_map),use_container_width=True,hide_index=True)
            if inventory.empty:
                st.error('No product rows were detected. Ensure the workbook has a Product/Product Name column and non-empty product values.')
            else:
                st.success(f'{len(inventory)} product rows detected across product-bearing sheets.')
                st.dataframe(inventory.head(100),use_container_width=True,hide_index=True)
                st.session_state.assessment_inventory=inventory.copy()
                pages_per_product=st.slider('Pages to attempt per product',5,20,5,help='The crawler attempts at least five URLs per product when enough accessible source URLs can be discovered. Actual successful reads are reported separately.')
                st.caption('Research is limited by vendor site access, robots.txt, network availability, and login requirements. Exact source URLs are retained; missing evidence remains Unknown.')
                if st.button('Research ALL products and build compatibility table',type='primary',use_container_width=True):
                    all_compat=[]; all_evidence=[]; progress=st.progress(0,text='Preparing product research…')
                    total=len(inventory)
                    for n, item in enumerate(all_rows):
                        vendor_name=item['Vendor'] or 'Unknown vendor'
                        product_name=item['Product']; release_name=item['Release']
                        # Resolve matching vendor source seeds without assuming an unknown vendor's identity.
                        registry_seeds=[]
                        for registry_vendor, urls in st.session_state.registry.items():
                            if vendor_name.lower() in registry_vendor.lower() or registry_vendor.lower() in vendor_name.lower():
                                registry_seeds.extend(urls)
                        row_url=item['Source URL']
                        seeds=[]
                        if row_url.startswith(('http://','https://')): seeds.append(row_url)
                        seeds.extend(registry_seeds)
                        # Fallback to known official directories by vendor-name hints.
                        low_vendor=vendor_name.lower()
                        if any(x in low_vendor for x in ['broadcom','ca technologies']): seeds.extend(DEFAULT_REGISTRY['Broadcom'])
                        if 'bmc' in low_vendor: seeds.extend(DEFAULT_REGISTRY['BMC'])
                        if any(x in low_vendor for x in ['rocket','asg']): seeds.extend(DEFAULT_REGISTRY['Rocket Software / ASG'])
                        if 'ibm' in low_vendor: seeds.extend(DEFAULT_REGISTRY['IBM'])
                        seeds=list(dict.fromkeys(u for u in seeds if u.startswith(('http://','https://'))))
                        # Research each product individually; don't merge PTF candidates across products.
                        records, visited=crawl(seeds,product_name,release_name,pages_per_product,delay=0.35) if seeds else ([],[])
                        for rec in records:
                            rec.update({'Vendor input':vendor_name,'Product input':product_name,'Release input':release_name,'Source sheet':item['Source sheet'],'Source row':item['Source row']})
                        all_evidence.extend(records)
                        usable=[r for r in records if r.get('Relevant')=='Yes']
                        for version in ZOS_VERSIONS:
                            # Compatibility is only considered verified when a vendor matrix explicitly ties this product to this OS.
                            status='Unknown — no explicit product/version evidence found'
                            proof=[]; ptf_values=[]; apar_values=[]
                            for rec in usable:
                                ctx=str(rec.get('Evidence '+version,''))
                                if ctx:
                                    lower=ctx.lower()
                                    if re.search(r'\b(no|not compatible|not supported|unsupported)\b',lower) and re.search(r'z/?os|v3r2|v3r1|v2r5|2\.5|3\.1|3\.2',lower):
                                        status='No — candidate evidence; review required'; proof.append(rec.get('URL',''))
                                    elif re.search(r'\b(yes|certified|compatible|supported)\b',lower) and re.search(r'z/?os|v3r2|v3r1|v2r5|2\.5|3\.1|3\.2',lower):
                                        status='Potential Yes — explicit confirmation required'; proof.append(rec.get('URL',''))
                                if rec.get('PTF candidates') not in ('','None extracted','Unknown','Not checked'):
                                    ptf_values.extend(x.strip() for x in str(rec['PTF candidates']).split(',') if x.strip())
                                if rec.get('APAR candidates') not in ('','None extracted','Unknown','Not checked'):
                                    apar_values.extend(x.strip() for x in str(rec['APAR candidates']).split(',') if x.strip())
                            # Preserve source workbook values but never pretend they were web-verified.
                            source_compat=item['Source compatibility'] or 'Not provided'
                            source_ptf=item['Source PTF'] or 'Not provided'
                            urls=list(dict.fromkeys([u for u in [item['Source URL']] + proof if u and u.startswith(('http://','https://'))]))
                            ptf_specific, apar_specific, fixcats = [], [], set()
                            sysmods = set(ptf_values) | set(apar_values)
                            for rec in usable:
                                for field, target in [('PTF-specific links', ptf_specific), ('APAR-specific links', apar_specific)]:
                                    raw = str(rec.get(field, ''))
                                    if raw and not raw.startswith('No direct'):
                                        target.extend(x.strip() for x in raw.split(';') if x.strip())
                                for token in re.findall(r'\b(?:IBM|CA|BROADCOM|BMC|HCL|ROCKET|MICROFOCUS)\.[A-Za-z0-9_.-]+', str(rec.get('Text excerpt','')), re.I):
                                    if re.search(r'FIXCAT|TargetSystem|RequiredService|Function', token, re.I): fixcats.add(token)
                            all_compat.append({'Vendor':vendor_name,'Product':product_name,'Release':release_name,'z/OS':version,'Compatible':status,
                                'PTFs (candidates)':'; '.join(sorted(set(ptf_values))) or (source_ptf if source_ptf != 'Not provided' else 'Not found'),
                                'PTF links (exact)':next((u.strip() for u in ptf_specific if u.strip().startswith(('https://','http://'))), 'No direct PTF URL found'),
                                'APARs (candidates)':'; '.join(sorted(set(apar_values))) or 'Not found',
                                'APAR links (exact)':next((u.strip() for u in apar_specific if u.strip().startswith(('https://','http://'))), 'No direct APAR URL found'),
                                'FIXCAT / SYSMOD':'; '.join(sorted(fixcats | sysmods | ({item['Message ID / FIXCAT']} if item['Message ID / FIXCAT'] else set()))) or 'Not found',
                                'Evidence links':'\n'.join(urls) if urls else 'No accessible evidence URL found',
                                'Pages read':sum(1 for x in records if x.get('Page title') not in ('Fetch error / inaccessible','Skipped by robots policy or robots.txt unavailable')),
                                'Review status':'Candidates only — verify exact release/applicability','Source sheet':item['Source sheet'],'Source row':item['Source row']})
                        progress.progress((n+1)/total,text=f'Researched {n+1} of {total}: {product_name}')
                    st.session_state.compatibility=pd.DataFrame(all_compat)
                    st.session_state.evidence=pd.DataFrame(all_evidence)
                    st.session_state.history.append({'Vendor':'All vendors','Product':f'Bulk research: {uploaded.name}','Release':'Multiple','Products processed':total,'Pages attempted':sum(int(x.get('Pages attempted',0)) for x in all_compat[::3]),'Records':len(all_evidence),'Checked UTC':datetime.now(timezone.utc).isoformat()})
                    st.success(f'Completed research attempts for {total} product rows; generated {len(all_compat)} compatibility rows and {len(all_evidence)} page-evidence records. Review all candidates before treating any status or PTF as authoritative.')
                    st.subheader('Compatibility and PTF results')
                    st.dataframe(st.session_state.compatibility,use_container_width=True,hide_index=True,column_config={'PTF links (exact)':st.column_config.LinkColumn('PTF detail URL'),'APAR links (exact)':st.column_config.LinkColumn('APAR detail URL'),'Evidence links':st.column_config.TextColumn('Evidence URLs')})
                    if not st.session_state.evidence.empty:
                        st.subheader('Pages actually fetched or attempted')
                        st.dataframe(st.session_state.evidence,use_container_width=True,hide_index=True,column_config={'URL':st.column_config.LinkColumn('Exact source URL')})
                st.download_button('Download detected product inventory CSV',inventory.to_csv(index=False).encode('utf-8-sig'),'mvs_bot_detected_inventory.csv','text/csv')
        except Exception as exc:
            st.error(f'Unable to read file: {exc}')
    st.markdown('**Important:** A product row is not considered compatible just because a page mentions the product. The app reports provisional candidates, exact URLs, and page-attempt counts. It cannot access customer-only portals unless the user has authorized access and provides supported credentials/integration.')
    template=pd.DataFrame([{'Vendor':'Example vendor','Product':'Example mainframe product','Release':'Exact release','Source compatibility':'Unknown','PTF Required':'','Source URL':'https://vendor.example.com/product-compatibility','Message ID / FIXCAT':'','Notes':'Replace with verified source data'}])
    st.download_button('Download blank input template',template.to_csv(index=False).encode('utf-8-sig'),'mvs_bot_input_template.csv','text/csv')

with registry_tab:
    st.subheader('Vendor source registry')
    st.caption('Start with known vendors, then add any mainframe ISV. Registry entries are source seeds, not a claim of complete vendor coverage.')
    for name, urls in st.session_state.registry.items():
        with st.expander(f'{name} — {len(urls)} source URL(s)', expanded=False):
            st.code('\n'.join(urls) if urls else 'No source URLs configured')
    st.markdown('#### Add vendor or source')
    new_vendor=st.text_input('Vendor / publisher name', key='new_vendor')
    new_urls=st.text_area('Official source URLs, one per line', key='new_urls')
    if st.button('Save vendor source entries'):
        if not new_vendor.strip(): st.error('Enter a vendor name.')
        else:
            current=st.session_state.registry.get(new_vendor.strip(),[])
            add=[u.strip() for u in new_urls.splitlines() if u.strip().startswith(('http://','https://'))]
            st.session_state.registry[new_vendor.strip()]=list(dict.fromkeys(current+add))
            st.success(f'Saved {len(add)} URL(s) for {new_vendor.strip()}.')
    seed_df=load_seed_data()
    st.markdown('#### Included seed catalogs')
    if not seed_df.empty:
        st.write(f'{len(seed_df)} combined source rows loaded from the supplied CSV catalogs.')
        st.dataframe(seed_df.head(200), use_container_width=True, hide_index=True)
        st.download_button('Download combined seed catalog', seed_df.to_csv(index=False).encode('utf-8-sig'), 'mvs_bot_seed_catalog.csv', 'text/csv')
    else: st.info('No seed CSVs found in the data folder.')

with history_tab:
    st.subheader('Research history (this session)')
    if st.session_state.history:
        hdf=pd.DataFrame(st.session_state.history)
        st.dataframe(hdf, use_container_width=True, hide_index=True)
        st.download_button('Download research history', hdf.to_csv(index=False).encode('utf-8-sig'), 'mvs_bot_research_history.csv', 'text/csv')
    else: st.info('No investigations in this session yet.')
    st.caption('History is held in Streamlit session state in this MVP. Persistent multi-user history requires a database.')

with reports_tab:
    st.subheader('Download report workbook')
    compat=st.session_state.compatibility.copy()
    evidence=st.session_state.evidence.copy()
    m1,m2,m3=st.columns(3)
    m1.metric('Compatibility rows', len(compat))
    m2.metric('Evidence records', len(evidence))
    m3.metric('Research sessions', len(st.session_state.history))
    if compat.empty:
        st.info('Run a lookup or validate an inventory to prepare report rows.')
    else:
        st.dataframe(compat, use_container_width=True, hide_index=True)
        report=workbook_bytes(compat, evidence, st.session_state.assessment_inventory if not st.session_state.assessment_inventory.empty else None, st.session_state.assessment_sheets)
        st.download_button('Download Excel report (.xlsx)', report, 'mvs_bot_compatibility_report.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', type='primary')
        st.download_button('Download compatibility CSV', compat.to_csv(index=False).encode('utf-8-sig'), 'mvs_bot_compatibility.csv', 'text/csv')

with st.sidebar:
    st.markdown('## MVS BOT')
    st.caption('Mainframe research workspace')
    st.markdown('**Target platforms**')
    for v in ZOS_VERSIONS: st.markdown(f'- z/OS {v}')
    st.divider()
    st.markdown('**Evidence policy**')
    st.caption('Unknown is a valid result. Never infer compatibility from absence of a warning. PTF candidates require release-specific validation.')
    st.divider()
    st.caption('MVP v1.2 • ISV assessment workbook integration • Local deployment')
