"""
app.py  –  Web interface for Log Analysis Tool
Run: python app.py  →  open http://localhost:5000
"""

from flask import Flask, render_template, request, jsonify
import os
import tempfile
from analyzer.log_parser import LogParser
from analyzer.anomaly_detector import AnomalyDetector, DetectorConfig

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400

    files = request.files.getlist('files')
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': 'No files selected'}), 400

    # Get threshold settings from form
    freq_threshold  = int(request.form.get('freq_threshold', 100))
    error_rate      = float(request.form.get('error_rate', 0.40))
    scan_paths      = int(request.form.get('scan_paths', 50))
    auth_fail       = int(request.form.get('auth_fail', 5))

    config = DetectorConfig(
        freq_req_threshold=freq_threshold,
        error_rate_threshold=error_rate,
        scan_distinct_paths=scan_paths,
        auth_fail_threshold=auth_fail,
    )
    detector = AnomalyDetector(config=config, ignore_private=False)
    parser   = LogParser()
    file_stats = []

    tmp_paths = []
    try:
        for f in files:
            if f.filename == '':
                continue
            # Save to temp file
            suffix = os.path.splitext(f.filename)[1] or '.log'
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
            f.save(tmp.name)
            tmp_paths.append((tmp.name, f.filename))

        for tmp_path, original_name in tmp_paths:
            before = parser.parsed_count
            detector.feed(parser.parse_file(tmp_path))
            after  = parser.parsed_count
            file_stats.append({'name': original_name, 'entries': after - before})

    finally:
        for tmp_path, _ in tmp_paths:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    anomalies = detector.detect()
    summary   = detector.summary()

    # Serialise anomalies for JSON
    anomaly_list = []
    for a in anomalies:
        anomaly_list.append({
            'ip':          a.ip,
            'type':        a.anomaly_type.value,
            'severity':    a.severity.value,
            'description': a.description,
            'evidence':    {k: (list(v) if isinstance(v, set) else v)
                           for k, v in a.evidence.items()},
            'first_seen':  a.first_seen.strftime('%Y-%m-%d %H:%M:%S') if a.first_seen else None,
            'last_seen':   a.last_seen.strftime('%Y-%m-%d %H:%M:%S')  if a.last_seen else None,
        })

    return jsonify({
        'summary':    summary,
        'anomalies':  anomaly_list,
        'file_stats': file_stats,
        'parser_stats': parser.stats(),
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)
