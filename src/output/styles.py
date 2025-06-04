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

        /* Section styles */
        .section {
            margin-bottom: 20px;
            padding: 15px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
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
        }

        .link-details {
            margin-top: 8px;
            font-size: 0.9em;
            color: #666;
        }

        /* Tab styles */
        .tab-container {
            display: flex;
            margin-bottom: 20px;
            gap: 5px;
        }

        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border: none;
            background: #f8f9fa;
            border-radius: 5px 5px 0 0;
            transition: all 0.2s ease;
        }

        .tab:hover {
            background: #e9ecef;
        }

        .tab.active {
            background: #fff;
            border-bottom: 2px solid #007bff;
            font-weight: 500;
        }

        /* Email content styles */
        .email-content {
            display: none;
        }

        .email-content.active {
            display: block;
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
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
        }

        /* Threat styles */
        .threats {
            color: #dc3545;
            margin-top: 5px;
            padding: 5px;
            background-color: #fff8f8;
            border-radius: 4px;
        }
    </style>
    """
