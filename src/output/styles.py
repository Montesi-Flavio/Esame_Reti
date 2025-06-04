"""
Definizioni CSS centralizzate per l'output HTML.
"""

def get_base_styles():
    """
    Restituisce gli stili CSS di base utilizzati in tutto il progetto.
    
    Returns:
        Stringa contenente il CSS
    """
    return """
    <style>
        /* Base styles */
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            overflow-x: hidden;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        /* Tab navigation styles */
        .tab-container {
            display: flex;
            background: white;
            border-radius: 8px 8px 0 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 0;
        }

        .tab {
            background: #f8f9fa;
            border: none;
            padding: 15px 25px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            color: #666;
            border-radius: 8px 8px 0 0;
            transition: all 0.3s ease;
            border-bottom: 3px solid transparent;
        }

        .tab:hover {
            background: #e9ecef;
            color: #333;
        }

        .tab.active {
            background: white;
            color: #007bff;
            border-bottom: 3px solid #007bff;
            box-shadow: 0 -2px 4px rgba(0,123,255,0.1);
        }

        .tab:first-child {
            border-radius: 8px 0 0 0;
        }

        .tab:last-child {
            border-radius: 0 8px 0 0;
        }

        /* Email content styles */
        .email-content {
            display: none;
            background: white;
            border-radius: 0 0 8px 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            padding: 20px;
            width: 100%;
            box-sizing: border-box;
            max-width: 1200px;
        }

        .email-content.active {
            display: block;
        }/* Section styles */
        .section {
            margin-bottom: 20px;
            padding: 15px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        /* Section styles inside email content */        .email-content .section {
            background: transparent;
            box-shadow: none;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            width: 100%;
            box-sizing: border-box;
        }

        .section h3 {
            margin-top: 0;
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        
        /* Email card styles */
        .email-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            padding: 20px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .email-card:hover {
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            transform: translateY(-1px);
        }
        
        .email-card.suspicious {
            border-left: 4px solid #dc3545;
        }
        
        .email-card.active {
            background-color: #f8f9fa;
            border-color: #007bff;
        }

        /* Link styles */
        .link-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .link-item {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            background-color: #f8f9fa;
            transition: all 0.2s ease;
        }

        .link-item:hover {
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }

        .link-item.safe-link { border-left: 4px solid #28a745; }
        .link-item.warning-link { border-left: 4px solid #ffc107; }
        .link-item.danger-link { border-left: 4px solid #dc3545; }

        .link-url a {
            color: #0066cc;
            text-decoration: none;
            word-break: break-all;
            transition: color 0.2s ease;
        }

        .link-url a:hover {
            color: #004c99;
            text-decoration: underline;
        }        .link-details {
            margin-top: 8px;
            font-size: 0.9em;
            color: #666;
        }

        /* Table styles */
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
            background: white;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
            vertical-align: top;
        }

        th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }

        /* Alert styles */
        .alert {
            padding: 12px 20px;
            margin-bottom: 15px;
            border: 1px solid transparent;
            border-radius: 4px;
            font-size: 14px;
        }

        .alert-success {
            color: #0f5132;
            background-color: #d1e7dd;
            border-color: #badbcc;
        }

        .alert-danger {
            color: #842029;
            background-color: #f8d7da;
            border-color: #f5c2c7;
        }

        .alert-warning {
            color: #664d03;
            background-color: #fff3cd;
            border-color: #ffecb5;
        }

        /* Badge styles */
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: 600;
        }

        .badge-success { 
            background-color: #d4edda; 
            color: #155724; 
        }

        .badge-warning { 
            background-color: #fff3cd; 
            color: #856404; 
        }

        .badge-danger { 
            background-color: #f8d7da; 
            color: #721c24; 
        }

        /* Details element styles */
        details {
            margin: 10px 0;
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 4px;
            border: 1px solid #dee2e6;
        }

        details summary {
            cursor: pointer;
            padding: 5px;
            font-weight: 500;
            color: #495057;
            transition: color 0.2s ease;
        }

        details summary:hover {
            color: #0066cc;
        }

        details[open] summary {
            margin-bottom: 10px;
            border-bottom: 1px solid #dee2e6;
        }

        /* Attachment styles */
        .attachment-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            background: white;
            transition: all 0.2s ease;
        }

        .attachment-card:hover {
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }

        .attachment-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }

        .attachment-name {
            font-weight: 500;
            color: #212529;
            flex: 1;
        }

        .hash-info {
            font-family: monospace;
            font-size: 0.9em;
            word-break: break-all;
            margin: 5px 0;
            padding: 8px;
            background: #f8f9fa;
            border-radius: 4px;
        }

        .hash-label {
            font-weight: bold;
            color: #6c757d;
            margin-right: 5px;
        }

        /* Responsive styles */
        @media screen and (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .email-card {
                padding: 15px;
            }
            
            th {
                display: none;
            }
            
            td {
                display: block;
                padding: 8px;
            }
            
            td::before {
                content: attr(data-label);
                font-weight: bold;
                display: block;
                margin-bottom: 5px;
            }
        }

        @media screen and (max-width: 480px) {
            body {
                padding: 10px;
            }
            
            .section {
                padding: 10px;
            }
            
            .tab {
                padding: 8px 12px;
                font-size: 14px;
            }
        }

        /* Accordion styles */
        .accordion .card {
            margin-bottom: 5px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        .accordion .card-header {
            padding: 0;
            background: #f8f9fa;
        }

        .accordion .btn-link {
            display: block;
            width: 100%;
            padding: 12px 20px;
            text-align: left;
            color: #0066cc;
            text-decoration: none;
            transition: all 0.2s ease;
        }

        .accordion .btn-link:hover {
            background: #e9ecef;
            text-decoration: none;
        }

        .accordion .collapse {
            border-top: 1px solid #ddd;
        }

        .accordion .card-body {
            padding: 15px;
        }        /* Threat styles */
        .threats {
            color: #dc3545;
            margin-top: 5px;
            padding: 5px;
            background-color: #fff8f8;
            border-radius: 4px;
        }

        /* Header display styles */
        .headers-container {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
        }

        .header-item {
            display: flex;
            flex-direction: column;
            margin-bottom: 12px;
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
        }

        .header-item:last-child {
            border-bottom: none;
        }

        .header-label {
            font-weight: 600;
            color: #495057;
            margin-bottom: 4px;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .header-value {
            color: #212529;
            font-size: 0.95em;
            line-height: 1.4;
        }

        .header-value h4 {
            margin: 0 0 5px 0;
            color: #0066cc;
            font-size: 1.1em;
        }

        .header-value strong {
            color: #2c5aa0;
        }

        .header-value code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #d63384;
        }

        .header-value em {
            color: #6c757d;
            font-style: normal;
            font-weight: 500;
        }

        .header-section-expandable {
            margin: 15px 0;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            overflow: hidden;
        }

        .header-section-expandable details {
            margin: 0;
            border: none;
        }

        .header-section-expandable summary {
            background: #e9ecef;
            padding: 12px 15px;
            cursor: pointer;
            user-select: none;
            font-weight: 600;
            color: #495057;
            transition: background-color 0.2s ease;
        }

        .header-section-expandable summary:hover {
            background: #dee2e6;
        }

        .expandable-content {
            padding: 15px;
            background: white;
        }

        .headers-basic {
            background: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
        }

        .headers-basic .header-item {
            display: flex;
            flex-direction: row;
            align-items: flex-start;
            gap: 10px;
            margin-bottom: 8px;
            padding: 6px 0;
        }        .headers-basic .header-item strong {
            min-width: 120px;
            color: #495057;
        }

        /* Investigation card styles */
        .investigation-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 15px;
            background: white;
            overflow: hidden;
        }

        .investigation-header {
            background: #f8f9fa;
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
        }

        .investigation-header h4 {
            margin: 0;
            color: #495057;
        }

        .investigation-content {
            padding: 15px;
        }

        .investigation-links {
            margin-top: 10px;
        }

        .investigation-links .btn {
            margin-right: 8px;
            margin-bottom: 5px;
        }

        .btn {
            display: inline-block;
            padding: 6px 12px;
            font-size: 14px;
            border-radius: 4px;
            text-decoration: none;
            transition: all 0.2s ease;
        }

        .btn-outline-primary {
            color: #007bff;
            border: 1px solid #007bff;
            background: white;
        }

        .btn-outline-primary:hover {
            background: #007bff;
            color: white;
        }

        .btn-outline-secondary {
            color: #6c757d;
            border: 1px solid #6c757d;
            background: white;
        }        .btn-outline-secondary:hover {
            background: #6c757d;
            color: white;
        }

        /* Attachment styles */
        .attachments-container {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        .attachment-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            background: white;
            transition: all 0.2s ease;
        }

        .attachment-card:hover {
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }

        .attachment-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #eee;
        }

        .attachment-name {
            font-size: 1.1em;
            color: #212529;
        }

        .attachment-details {
            margin-top: 10px;
        }

        .attachment-info {
            margin-bottom: 10px;
            line-height: 1.5;
        }

        .hash-section {
            margin: 10px 0;
        }

        .hash-content {
            margin-top: 8px;
        }

        .hash-item {
            display: flex;
            align-items: center;
            margin-bottom: 5px;
            padding: 5px;
            background: #f8f9fa;
            border-radius: 4px;
        }

        .hash-label {
            font-weight: bold;
            min-width: 60px;
            color: #495057;
        }

        .hash-value {
            flex: 1;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }

        .hash-value a {
            color: #007bff;
            text-decoration: none;
        }

        .hash-value a:hover {
            text-decoration: underline;
        }

        .security-analysis {
            margin-top: 15px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }

        .security-analysis h5 {
            margin: 0 0 8px 0;
            color: #495057;
        }

        .security-details {
            margin-top: 8px;
        }

        .security-details ul {
            margin: 5px 0;
            padding-left: 20px;
        }

        .file-link {
            margin-top: 10px;
            padding: 8px;
            background: #e9ecef;
            border-radius: 4px;
        }

        .file-link a {
            color: #007bff;
            text-decoration: none;
        }

        .file-link a:hover {
            text-decoration: underline;
        }

        /* DMARC styles */
        .dmarc-container {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        .dmarc-record {
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
            background: white;
        }

        .dmarc-status {
            padding: 15px;
            font-weight: 500;
        }

        .dmarc-status.success {
            background: #d4edda;
            border-color: #c3e6cb;
            color: #155724;
        }

        .dmarc-status.danger {
            background: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
        }

        .dmarc-status h4 {
            margin: 0;
        }

        .dmarc-details {
            padding: 15px;
            border-top: 1px solid #ddd;
        }

        .dmarc-record-text {
            margin-top: 8px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
            border: 1px solid #dee2e6;
        }

        .dmarc-record-text code {
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
            color: #495057;
        }

        .dmarc-policy {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            margin-top: 10px;
        }

        .dmarc-policy h5 {
            margin: 0 0 10px 0;
            color: #495057;
        }        .dmarc-warning {
            padding: 15px;
        }

        /* DKIM Analysis Styles */
        .dkim-analysis {
            margin-top: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
            background: white;
        }

        .dkim-analysis h5 {
            margin: 0;
            padding: 15px;
            background: #f8f9fa;
            border-bottom: 1px solid #ddd;
            color: #495057;
            font-weight: 600;
        }

        .auth-status-box {
            padding: 15px;
        }

        .status-item {
            display: flex;
            align-items: center;
            padding: 10px;
            border-radius: 6px;
            margin-bottom: 10px;
            font-weight: 500;
        }

        .status-item.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .status-item.danger {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .status-icon {
            margin-right: 10px;
            font-size: 16px;
        }

        .status-text {
            font-weight: 500;
        }

        .dkim-details {
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
        }

        .dkim-details h6 {
            margin: 0 0 15px 0;
            color: #495057;
            font-weight: 600;
        }

        .dkim-details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 12px;
            margin-bottom: 15px;
        }

        .detail-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 12px;
            background: white;
            border-radius: 4px;
            border: 1px solid #dee2e6;
        }

        .detail-label {
            font-weight: 600;
            color: #495057;
            margin-right: 10px;
        }

        .detail-value {
            color: #6c757d;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }

        .signed-headers {
            margin-top: 15px;
        }

        .signed-headers h6 {
            margin: 0 0 10px 0;
            color: #495057;
            font-weight: 600;
        }

        .headers-list {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }

        .header-tag {
            background: #e9ecef;
            color: #495057;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-family: 'Courier New', monospace;
            border: 1px solid #ced4da;
        }

        .body-hash-status {
            margin-top: 10px;
            padding: 8px 12px;
            background: white;
            border-radius: 4px;
            border: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .domain-info {
            margin-bottom: 20px;
            padding: 15px;
            background: #e3f2fd;
            border-radius: 8px;
            border-left: 4px solid #2196f3;
        }

        .domain-info h4 {
            margin: 0;
            color: #1565c0;
            font-weight: 600;
        }

        .auth-results {
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }

        .auth-results h5 {
            margin: 0 0 15px 0;
            color: #495057;
        }

        .auth-details {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .auth-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px;
            background: white;
            border-radius: 4px;
            border: 1px solid #dee2e6;
        }

        .auth-type {
            font-weight: 600;
            color: #495057;
        }

        /* Alert styles */
        .alert {
            padding: 12px 20px;
            margin-bottom: 15px;
            border: 1px solid transparent;
            border-radius: 4px;
            font-size: 14px;
        }

        .alert-success {
            color: #0f5132;
            background-color: #d1e7dd;
            border-color: #badbcc;
        }

        .alert-danger {
            color: #842029;
            background-color: #f8d7da;
            border-color: #f5c2c7;
        }

        .alert-warning {
            color: #664d03;
            background-color: #fff3cd;
            border-color: #ffecb5;
        }

        .alert-info {
            color: #055160;
            background-color: #cff4fc;
            border-color: #b6effb;
        }
    </style>
    """
