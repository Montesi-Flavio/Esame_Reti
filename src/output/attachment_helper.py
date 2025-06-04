"""
Funzione per generare il codice HTML per la sezione degli allegati.
Questa funzione è stata creata per sostituire la sezione con problemi nel file html_output.py.
"""
def generate_attachment_section(result):
    """
    Genera il codice HTML per la sezione degli allegati.
    
    Args:
        result: Risultato dell'analisi per una singola email
    
    Returns:
        Stringa con il codice HTML per la sezione degli allegati
    """
    from html import escape
    
    html = """
    <div class="section">
        <h2>Allegati</h2>
        <table>
            <tr>
                <th>Nome File</th>
                <th>Tipo</th>
                <th>Dimensione</th>
            </tr>
    """
    
    attachments = result["Attachments"].get("Attachments", {})
    
    if isinstance(attachments, list) and attachments:
        for attachment in attachments:
            if isinstance(attachment, dict):
                filename = attachment.get('filename', 'Sconosciuto')
                content_type = attachment.get('content_type', 'Sconosciuto') or attachment.get('mime_type', 'Sconosciuto')
                size = attachment.get('size', 'Sconosciuto')
            else:
                filename = str(attachment)
                content_type = 'Sconosciuto'
                size = 'Sconosciuto'
            
            html += f"""
                <tr>
                    <td>{escape(str(filename))}</td>
                    <td>{escape(str(content_type))}</td>
                    <td>{escape(str(size))}</td>
                </tr>
            """
    elif isinstance(attachments, dict) and attachments:
        for idx, attachment in attachments.items():
            if isinstance(attachment, dict):
                filename = attachment.get('Filename', attachment.get('filename', 'Sconosciuto'))
                content_type = attachment.get('MIME Type', attachment.get('mime_type', 'Sconosciuto'))
                size = attachment.get('Size', attachment.get('size', 'Sconosciuto'))
                
                html += f"""
                    <tr>
                        <td>{escape(str(filename))}</td>
                        <td>{escape(str(content_type))}</td>
                        <td>{escape(str(size))}</td>
                    </tr>
                """
    else:
        html += """
            <tr>
                <td colspan="3">Nessuna informazione sugli allegati disponibile</td>
            </tr>
        """
    
    html += """
        </table>
    </div>
    """
    
    return html
