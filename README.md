# MVS BOT — Bulk Mainframe Compatibility & PTF Research

This Streamlit MVP imports **all product-bearing sheets** from an Excel workbook or CSV, consolidates non-empty product rows, and runs a bounded web research attempt for each row. It creates a compatibility table for z/OS 2.5, 3.1, and 3.2 with source workbook values, extracted PTF/APAR candidates, page counts, and exact evidence URLs.

## Run on Windows

```bat
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Bulk workflow

1. Open **Excel Bulk Upload**.
2. Upload `ISV Compatibility assessment.xlsx` (or another `.xlsx`, `.xls`, or `.csv` inventory).
3. Review the sheet/column mapping and detected product inventory. Product-bearing sheets are combined; sheets without a product column are preserved in the output as original source sheets.
4. Set **Pages to attempt per product** (minimum 5) and click **Research ALL products and build compatibility table**.
5. Review the generated compatibility/PTF table and evidence pages. Use the Reports tab to export the report workbook.

The supplied assessment workbook is included as `data/ISV_Compatibility_assessment_original.xlsx`; it is kept as a source copy and not overwritten.

## Evidence and correctness policy

- z/OS 2.5, 3.1, and 3.2 are separate results. The workbook's z/OS 3.2 field is preserved only as source data; it does not establish z/OS 2.5/3.1 support.
- Compatibility findings and extracted PTF/APARs are **candidates**, not authoritative installation instructions. A product mention or an extracted PTF identifier alone does not prove applicability to the exact release/OS.
- The crawler attempts up to the configured number of URLs per product, follows scored same-domain links, checks `robots.txt`, and does not bypass login/MFA. The UI records successful evidence pages separately from attempted URLs. Five pages cannot be guaranteed if the site has fewer relevant public pages, denies crawling, or is inaccessible.
- Exact source URLs and page excerpts are retained for review. Before applying maintenance, verify the exact release and PTF prerequisites against official vendor documentation, SMP/E HOLDDATA, FIXCAT, and installation instructions.
- Some ISV support information requires an authorized customer login; the MVP does not bypass access controls.

## Included data

- `data/ISV_Compatibility_assessment_original.xlsx`
- `data/asg_compat.csv`
- `data/bmc_compat.csv`
- `data/broadcom_compat.csv`

## Scope

This is a local MVP. It does not promise discovery of every mainframe vendor, does not provide credentials for vendor portals, and has not been end-to-end validated against every ISV. Add official source URLs in **Vendor Registry** and validate output before using it for change planning.
