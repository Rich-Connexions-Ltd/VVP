# Plan: Enhanced Credential Card UI

## 1. Problem Statement
Recent sprints have introduced complex Tier 2/3 functionality: ACDC credentials, schema validation, revocation checking (TEL), and trust chains (APE/TNAlloc/vLEI).
The current UI does not adequately visualize these rich data structures or their validation states. Users (Agents/Admins) need to see *why* a call is verified, not just a green checkmark.

## 2. Design Goals
*   **Transparency:** Visualize the "Why". Show the chain of trust (e.g., "This caller is authorized by Company X, who is a Qualified vLEI Issuer trusted by GLEIF").
*   **Hierarchy:** distinct visuals for different credential types (APE vs vLEI vs TNAlloc).
*   **Responsiveness:** Card must adapt from desktop (admin dashboard) to mobile (field agent).
*   **HTMX-Native:** Lazy loading of heavy data (revocation status, chain details) to keep initial load fast.

## 3. Data Requirements
The card must display:
1.  **Credential Type (Schema):** APE, DE, TNAlloc, vLEI, or Unknown.
2.  **Subject Attributes:** Critical fields (e.g., Phone Number for APE, Legal Name for vLEI).
3.  **Validation Status:** Values from `ClaimStatus` (VALID, INVALID, REVOKED, INDETERMINATE).
4.  **Issuer Identity:** AID of the issuer + "Trusted Root" indicator if applicable.
5.  **Revocation State:** Last checked time + Source (Witness/OOBI).
6.  **Trust Chain:** Link to the parent credential (e.g., "Vetted By").

## 4. UI Layout & Component Design

### 4.1 Card Container
A visually distinct container using the project's CSS variables (e.g., surface color, border radius).
*   **State Styling:** Border color reflects status (Green=Valid, Red=Invalid/Revoked, Yellow=Indeterminate).

### 4.2 Anatomy of the Card

| Section | Elements | Layout (Flex/Grid) |
| :--- | :--- | :--- |
| **Header** | **Icon** (Schema-specific)<br>**Title** (Schema Friendly Name)<br>**Badge** (Status) | Flex Row (Space Between) |
| **Body** | **Primary Attribute** (Large, e.g., LE Name)<br>**Secondary Attributes** (Key-Value pairs) | Vertical Stack or Grid |
| **Meta** | **Issuer:** "Issued by [AID Short]"<br>**Date:** "Issued: [Date]" | Flex Row (Small text) |
| **Footer** | **Chain Link:** "↗ Vetted by [Parent]"<br>**Actions:** "Details" | Flex Row (Right Aligned) |

### 4.3 Schema-Specific Variations
*   **APE (Auth Phone Entity):**
    *   *Icon:* Phone/Smartphone
    *   *Primary:* The Phone Number (`+1-555-0100`)
    *   *Context:* Focus on the "Right to Use".
*   **vLEI (Legal Entity):**
    *   *Icon:* Building/Business
    *   *Primary:* Legal Entity Name ("Acme Corp")
    *   *Context:* Focus on Identity.
*   **TNAlloc (Allocation):**
    *   *Icon:* Map/Grid
    *   *Primary:* Number Block (`+1-555-XXXX`)
    *   *Context:* Focus on Range Ownership.

### 4.4 HTMX Interactions
1.  **Lazy Revocation Check:**
    *   The revocation status badge loads lazily via `hx-trigger="load"`.
    *   *Endpoint:* `POST /check-revocation/html` (returns a `<span class="badge">`).
2.  **Chain Expansion:**
    *   The "Vetted by" or "Parent" link uses `hx-get="/credentials/{said}/html"` to append the parent card below the current one (accordion style).
    *   Allows exploring the chain without reloading.
3.  **Detail View:**
    *   Clicking "Details" expands a `<details>` block with raw JSON/CESR data (for debugging).

## 5. Technical Implementation

### 5.1 Jinja2 Template macro (`macros/credential_card.html`)

```html
{% macro credential_card(acdc, status, type="generic") %}
<article class="credential-card status-{{ status.lower() }}" data-said="{{ acdc.said }}">
  <header>
    <div class="schema-icon" data-type="{{ type }}">
       <!-- SVG Icon based on type -->
    </div>
    <h3>{{ type | title }}</h3>
    <span class="badge {{ status.lower() }}">{{ status }}</span>
  </header>
  
  <div class="card-body">
    {% if type == 'APE' %}
      <div class="primary-attr">{{ acdc.attributes.number }}</div>
    {% elif type == 'vLEI' %}
      <div class="primary-attr">{{ acdc.attributes.legalName }}</div>
    {% endif %}
    
    <dl class="attrs-grid">
      <!-- Loop top 3 other attributes -->
    </dl>
  </div>

  <div class="card-meta">
    <small>Issued by: <span class="mono">{{ acdc.issuer | truncate(16) }}</span></small>
    <!-- HTMX Lazy Load Revocation -->
    <div hx-post="/check-revocation/html" 
         hx-vals='{"credential_said": "{{ acdc.said }}"}'
         hx-trigger="load"
         hx-swap="outerHTML">
       <span class="spinner">Checking status...</span>
    </div>
  </div>
  
  <footer>
    {% if acdc.edges.vetting %}
      <a href="#" 
         hx-get="/credential/{{ acdc.edges.vetting.n }}/html"
         hx-target="#chain-container-{{ acdc.said }}"
         hx-swap="beforeend">
         View Vetting Credential →
      </a>
    {% endif %}
    <div id="chain-container-{{ acdc.said }}"></div>
  </footer>
</article>
{% endmacro %}
```

### 5.2 CSS Logic (Responsive)
*   **Mobile:** Cards stack vertically. Font sizes specific to readablity.
*   **Desktop:** Cards can be in a masonry grid or horizontal chain visualization.
*   **Variables:**
    *   `--status-valid: #2ecc71;`
    *   `--status-invalid: #e74c3c;`
    *   `--status-revoked: #c0392b;`

## 6. User Experience Walkthrough
1.  **Agent Logic:** Agent sees an incoming call request on the dashboard.
2.  **Initial View:** A high-level summary card (the "Leaf" credential) appears. It says "APE: +15550100" with a Green Badge.
3.  **Investigation:** Agent clicks "View Vetting Credential".
4.  **Chain Reveal:** The UI inserts the vLEI card below/next to the APE card. It shows "Acme Corp".
5.  **Trust Confirmation:** User sees the "Trusted Root" badge on the vLEI card (issued by QVI).
6.  **Decision:** Agent answers confidently.

## 7. Next Steps
1.  **Mockup:** Create the HTML/CSS prototype in `templates/components/credential_card.html`.
2.  **Backend Support:** Ensure `ACDC` objects have a `type` property inferred from schema SAID.
3.  **Integration:** Use this macro in the `verify_result.html` template.
