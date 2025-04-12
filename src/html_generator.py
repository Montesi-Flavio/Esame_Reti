import json
from html import escape

def generate_headers_section(headers):
    # Data
    ######################################################################
    html = """
        <h2 id="headers-section" style="text-align: center;"><i class="fa-solid fa-code"></i> Headers</h2>
        <hr>
        <h3 id="headers-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
    """
    
    # Utilizzo della versione HTML formattata se disponibile
    if "HTML_View" in headers:
        html_view = headers["HTML_View"]
        html += """
        <div class="card mb-4">
            <div class="card-header bg-light">
                <h4 class="card-title">Informazioni Email</h4>
            </div>
            <div class="card-body">
                <table class="table table-sm">
                    <tbody>
        """
        
        # Inserisci i valori formattati per HTML
        for label, value in html_view.items():
            html += f"<tr><th>{label}</th><td>{value}</td></tr>"
            
        html += """
                    </tbody>
                </table>
            </div>
        </div>
        """
    else:
        # Fallback alla vecchia formattazione per compatibilità
        html += """
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
        """
        for key, value in headers["Data"].items():
            # Populate table rows
            html += f"<tr><td>{ str(key) }</td><td>{ escape(str(value)) }</td></tr>"
            
        html += """
            </tbody>
        </table>
        """
    
    ######################################################################
    
    # Investigation
    ######################################################################
    html += """
        <h3 id="headers-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
    """
    
    # Utilizzo della versione HTML formattata per l'investigazione se disponibile
    if "HTML_Investigation" in headers:
        html += """<div class="row">"""
        
        for section_name, html_content in headers["HTML_Investigation"].items():
            html += f"""
            <div class="col-md-6 mb-4">
                {html_content}
            </div>
            """
        
        html += "</div>"
    else:
        # Fallback alla vecchia formattazione per compatibilità
        html += """<div class="row">"""
        
        for index, values in headers["Investigation"].items():
            # Populate table rows
            html += """
            <div class="col-md-4">
                <div class="jumbotron">
                    <h3>{}</h3><hr>
            """.format(index)
            for k, v in values.items():
                html += f"<br><b>{k}:<br></b>{v}"
            
            html += """
                </div>
            </div>
            """

    html += "</div><hr>"
    return html
    ######################################################################

def generate_links_section(links):
    # Data
    ######################################################################
    html = """
        <h2 id="links-section" style="text-align: center;"><i class="fa-solid fa-link"></i> Links</h2>
        <hr>
        <h3 id="links-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in links["Data"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>{}</td>".format(key,value)
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += """
        <h3 id="links-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Link</th>
                    <th>Information</th>
                </tr>
            </thead>
        <tbody>
    """
    for index,values in links["Investigation"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>".format(index)
        for k,v in values.items():
            html += f"<b>{k}</b>: Potentially suspicious"
        html += "</td></tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_attachment_section(attachments):
    # Data
    ######################################################################
    html = """
        <h2 id="attachments-section" style="text-align: center;"><i class="fa-solid fa-paperclip"></i> Attachments</h2>
        <hr>
        <h3 id="attachments-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    
    # Verifica che ci siano dati disponibili
    if "Data" in attachments and attachments["Data"]:
        for key, value in attachments["Data"].items():
            # Populate table rows with proper escaping
            html += "<tr>"
            html += "<td>{}</td><td>{}</td>".format(
                escape(str(key)) if key is not None else "",
                escape(str(value)) if value is not None else ""
            )
            html += "</tr>"
    else:
        html += "<tr><td colspan='2'>No attachment data found</td></tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += """
        <h3 id="attachments-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <div class="row">
    """
    
    # Verifica che ci siano dati di investigazione disponibili
    if "Investigation" in attachments and attachments["Investigation"]:
        for index, values in attachments["Investigation"].items():
            try:
                # Verifica se abbiamo un formato HTML_View predefinito
                if isinstance(values, dict) and "HTML_View" in values:
                    html_view = values["HTML_View"]
                    html += """
                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header">
                                <h4 class="card-title">{}</h4>
                            </div>
                            <div class="card-body">
                                <table class="table table-sm">
                                    <tbody>
                    """.format(escape(str(index)))
                    
                    # Inserisci i valori formattati per HTML
                    if isinstance(html_view, dict):
                        for label, value in html_view.items():
                            safe_value = escape(str(value)) if value is not None else ""
                            html += f"<tr><th>{escape(str(label))}</th><td>{safe_value}</td></tr>"
                    
                    # Se ci sono formatted results di VirusTotal, li aggiungiamo
                    if "HTML_Formatted" in values and isinstance(values["HTML_Formatted"], dict):
                        html += """
                        <tr>
                            <th colspan="2" class="bg-light">Analisi VirusTotal</th>
                        </tr>
                        """
                        for hash_type, hash_data in values["HTML_Formatted"].items():
                            if isinstance(hash_data, dict) and "Tipo" in hash_data and "Link VirusTotal" in hash_data and "Rilevamenti" in hash_data:
                                html += f"""<tr>
                                    <th>{escape(str(hash_data['Tipo']))}</th>
                                    <td>{escape(str(hash_data['Link VirusTotal']))} - {escape(str(hash_data['Rilevamenti']))}</td>
                                </tr>"""
                    
                    html += """
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    """
                else:
                    # Fallback alla vecchia formattazione per compatibilità con gestione errori migliorata
                    html += """
                    <div class="col-md-6 mb-4">
                        <div class="card">
                            <div class="card-header">
                                <h4 class="card-title">{}</h4>
                            </div>
                            <div class="card-body">
                    """.format(escape(str(index)))
                    
                    if isinstance(values, dict):
                        for k, v in values.items():
                            if isinstance(v, dict):
                                for x, y in v.items():
                                    html += f"<p><strong>{escape(str(x))} ({escape(str(k))})</strong>: Potentially suspicious</p>"
                            else:
                                html += f"<p><strong>{escape(str(k))}</strong>: {escape(str(v))}</p>"
                    else:
                        html += "<p>Invalid data structure for this attachment</p>"
                    
                    html += """
                            </div>
                        </div>
                    </div>
                    """
            except Exception as e:
                # Gestione degli errori per evitare interruzioni
                html += f"""
                <div class="col-md-6 mb-4">
                    <div class="card border-danger">
                        <div class="card-header bg-danger text-white">
                            <h4 class="card-title">Error Processing Attachment</h4>
                        </div>
                        <div class="card-body">
                            <p>An error occurred while processing this attachment: {escape(str(e))}</p>
                            <p>Attachment ID: {escape(str(index))}</p>
                        </div>
                    </div>
                </div>
                """
    else:
        html += """
        <div class="col-12">
            <div class="alert alert-info">
                No investigation data available for attachments
            </div>
        </div>
        """
    
    html += """
        </div>
        <hr>"""

    return html
    ######################################################################

def generate_digest_section(digests):
    # Data
    ######################################################################
    html = """
        <h2 id="digests-section" style="text-align: center;"><i class="fa-solid fa-hashtag"></i> Digests</h2>
        <hr>
        <h3 id="digests-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in digests["Data"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>{}</td>".format(key,value)
        html += "</tr>"
        
    html += """
        </tbody>
    </table>"""
    ######################################################################

    # Investigation
    ######################################################################
    html += """
        <h3 id="digests-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Digest</th>
                    <th>Information</th>
                </tr>
            </thead>
        <tbody>
    """
    for index,values in digests["Investigation"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>".format(index)
        for k,v in values.items():
            html += f"<b>{k}</b>: Potentially suspicious<br>"
        html += "</td></tr>"
        
    html += """
        </tbody>
    </table>
    <hr>"""

    return html
    ######################################################################

def generate_table_from_json(json_obj):
    # Parse JSON object
    data = json_obj["Analysis"]
    info_data = json_obj["Information"]

    # Object Counts
    if data.get("Headers"):
        headers_cnt = len(data["Headers"]["Data"])
        headers_inv_cnt = len(data["Headers"]["Investigation"])
    else:
        headers_cnt = 0
        headers_inv_cnt = 0

    if data.get("Links"):
        links_cnt = len(data["Links"]["Data"])
        links_inv_cnt = len(data["Links"]["Investigation"])
    else:
        links_cnt = 0
        links_inv_cnt = 0

    if data.get("Attachments"):
        attach_cnt = len(data["Attachments"]["Data"])
        attach_inv_cnt = len(data["Attachments"]["Investigation"])
    else:
        attach_cnt = 0
        attach_inv_cnt = 0

    if data.get("Digests"):
        digest_cnt = len(data["Digests"]["Data"])
        digest_inv_cnt = len(data["Digests"]["Investigation"])
    else:
        digest_cnt = 0
        digest_inv_cnt = 0

    # Generate HTML table with Bootstrap classes (without external links)
    html = f"""
        <head>
            <style>
                /* Bootstrap-like styling embedded directly */
                .container-fluid {{
                    width: 100%;
                    padding-right: 15px;
                    padding-left: 15px;
                    margin-right: auto;
                    margin-left: auto;
                }}
                .row {{
                    display: flex;
                    flex-wrap: wrap;
                    margin-right: -15px;
                    margin-left: -15px;
                }}
                .col-md-6 {{
                    flex: 0 0 50%;
                    max-width: 50%;
                    padding-right: 15px;
                    padding-left: 15px;
                }}
                .col-md-4 {{
                    flex: 0 0 33.333333%;
                    max-width: 33.333333%;
                    padding-right: 15px;
                    padding-left: 15px;
                }}
                .table {{
                    width: 100%;
                    margin-bottom: 1rem;
                    color: #212529;
                    border-collapse: collapse;
                }}
                .table-bordered {{
                    border: 1px solid #dee2e6;
                }}
                .table-striped tbody tr:nth-of-type(odd) {{
                    background-color: rgba(0, 0, 0, 0.05);
                }}
                .table th, .table td {{
                    padding: 0.75rem;
                    vertical-align: top;
                    border-top: 1px solid #dee2e6;
                }}
                .table-bordered th, .table-bordered td {{
                    border: 1px solid #dee2e6;
                }}
                .jumbotron {{
                    padding: 2rem 1rem;
                    margin-bottom: 2rem;
                    background-color: #e9ecef;
                    border-radius: 0.3rem;
                }}
                .badge {{
                    display: inline-block;
                    padding: 0.25em 0.4em;
                    font-size: 75%;
                    font-weight: 700;
                    line-height: 1;
                    text-align: center;
                    white-space: nowrap;
                    vertical-align: baseline;
                    border-radius: 0.25rem;
                }}
                .badge-dark {{
                    color: #fff;
                    background-color: #343a40;
                }}
                .badge-pill {{
                    padding-right: 0.6em;
                    padding-left: 0.6em;
                    border-radius: 10rem;
                }}
            </style>
        </head>

        <div class="container-fluid">
        """
    
    html += f"""
        <h2 style="text-align: center;"><i class="fa-solid fa-circle-info"></i> Information</h2>
        <hr>
        <div class="row">
            <div class="col-md-6">
                <h3 style="text-align: center;"><i class="fa-solid fa-diagram-project"></i> Project</h3>
                <table class="table table-bordered table-striped">
                    <tbody>
                        <tr>
                            <td>Name</td>
                            <td>{ info_data["Project"]["Name"] }</td>
                        </tr>
                        <tr>
                            <td>Url</td>
                            <td>{ info_data["Project"]["Url"] }</td>
                        </tr>
                        <tr>
                            <td>Version</td>
                            <td>{ info_data["Project"]["Version"] }</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="col-md-6">
                <h3 style="text-align: center;"><i class="fa-solid fa-satellite-dish"></i> Scan</h3>
                <table class="table table-bordered table-striped">
                    <tbody>
                        <tr>
                            <td>Name</td>
                            <td>{ info_data["Scan"]["Filename"] }</td>
                        </tr>
                        <tr>
                            <td>Generated</td>
                            <td>{ info_data["Scan"]["Generated"] }</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    """

    if data.get("Headers"):
        html += generate_headers_section(data["Headers"])
    
    if data.get("Links"):
        html += generate_links_section(data["Links"])

    if data.get("Attachments"):
        html += generate_attachment_section(data["Attachments"])

    if data.get("Digests"):    
        html += generate_digest_section(data["Digests"])
    
    
    html += """
        </div>
    """

    return html