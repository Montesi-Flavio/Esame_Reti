import json
from html import escape

def generate_headers_section(headers):
    # Data
    ######################################################################
    html = """
        <h2 id="headers-section" style="text-align: center;"><i class="fa-solid fa-code"></i> Headers</h2>
        <hr>
        <h3 id="headers-data-section"><i class="fa-solid fa-chart-column"></i> Data</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
        <tbody>
    """
    for key,value in headers["Data"].items():
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
        <div class="row">
    """
    for index,values in headers["Investigation"].items():
        # Populate table rows
        html += """
        <div class="col-md-4">
            <div class="jumbotron">
                <h3>{}</h3><hr>
        """.format(index)
        for k,v in values.items():
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
    for key,value in attachments["Data"].items():
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
        <h3 id="attachments-investigation-section"><i class="fa-solid fa-magnifying-glass"></i> Investigation</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>Attachment</th>
                    <th>Information</th>
                </tr>
            </thead>
        <tbody>
    """
    for index,values in attachments["Investigation"].items():
        # Populate table rows
        html += "<tr>"
        html += "<td>{}</td><td>".format(index)
        for k,v in values.items():
            for x,y in v.items():
                html += f"<b>{x} ({k})</b>: Potentially suspicious<br>"
        html += "</td></tr>"
        
    html += """
        </tbody>
    </table>
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