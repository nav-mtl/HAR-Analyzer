import json
import re
from datetime import datetime, timedelta
from haralyzer import HarParser
from flask import Flask, request, render_template
import pandas as pd
import plotly.express as px
import plotly.io as pio

app = Flask(__name__)

# Define keywords for detecting sensitive information
keywords = ["auth", "token", "api", "key", "authorization", "bearer", "cookie", "username", "password", "session_id"]

def parse_har(har_content):
    """Parse HAR content and extract entries."""
    har_parser = HarParser(json.loads(har_content))
    entries = []
    for page in har_parser.pages:
        for entry in page.entries:
            start_time = datetime.fromisoformat(entry['startedDateTime'].replace('Z', '+00:00'))
            end_time = start_time + timedelta(milliseconds=entry['time'])
            request_body = entry['request'].get('postData', {}).get('text', '')
            response_body = entry['response'].get('content', {}).get('text', '')
            entries.append({
                'startedDateTime': start_time,
                'endDateTime': end_time,
                'time': entry['time'],
                'request_method': entry['request']['method'],
                'request_url': entry['request']['url'],
                'response_status': entry['response']['status'],
                'response_status_text': entry['response']['statusText'],
                'request_headers': entry['request']['headers'],  # Store as list of headers
                'response_headers': entry['response']['headers'],  # Store as list of headers
                'request_body': request_body[:500],  # Limit to first 500 characters
                'response_body': response_body[:500],  # Limit to first 500 characters
                'request_cookies': entry['request'].get('cookies', []),
                'response_cookies': entry['response'].get('cookies', [])
            })
    return entries

def generate_metrics(entries):
    """Generate metrics from HAR entries."""
    metrics = {
        'total_entries': len(entries),
        'total_time': sum(entry['time'] for entry in entries),
        'average_time': sum(entry['time'] for entry in entries) / len(entries) if entries else 0,
        'status_codes': {}
    }
    for entry in entries:
        status = entry['response_status']
        metrics['status_codes'][status] = metrics['status_codes'].get(status, 0) + 1
    return metrics

def extract_matching_lines(text, context):
    """Extract lines containing keywords and add context-specific comments."""
    lines = text.split('\n')
    matching_lines = []
    for line in lines:
        for keyword in keywords:
            if re.search(r'\b' + keyword + r'\b', line, re.IGNORECASE):
                matching_lines.append(f"Security Concern: The following content might contain {keyword}.")
                matching_lines.append(f"{line}")
                break
    return '\n'.join(matching_lines)

def check_security_issues(entries):
    """Check for security issues in HAR entries using keywords."""
    issues = []
    for entry in entries:
        request_body = entry['request_body']
        response_body = entry['response_body']
        request_headers = extract_matching_lines(
            '\n'.join(f"{header['name']}: {header['value']}" for header in entry['request_headers']), 'header')
        response_headers = extract_matching_lines(
            '\n'.join(f"{header['name']}: {header['value']}" for header in entry['response_headers']), 'header')
        request_cookies = extract_matching_lines(
            '\n'.join(f"{cookie['name']}: {cookie['value']}" for cookie in entry['request_cookies']), 'cookie')
        response_cookies = extract_matching_lines(
            '\n'.join(f"{cookie['name']}: {cookie['value']}" for cookie in entry['response_cookies']), 'cookie')
        request_url = entry['request_url']
        
        if contains_keywords(request_body):
            issues.append({
                'type': 'Request Body',
                'url': request_url,
                'content': extract_matching_lines(request_body, 'body')
            })
        if contains_keywords(response_body):
            issues.append({
                'type': 'Response Body',
                'url': request_url,
                'content': extract_matching_lines(response_body, 'body')
            })
        if request_headers:
            issues.append({
                'type': 'Request Headers',
                'url': request_url,
                'content': request_headers
            })
        if response_headers:
            issues.append({
                'type': 'Response Headers',
                'url': request_url,
                'content': response_headers
            })
        if request_cookies:
            issues.append({
                'type': 'Request Cookies',
                'url': request_url,
                'content': request_cookies
            })
        if response_cookies:
            issues.append({
                'type': 'Response Cookies',
                'url': request_url,
                'content': response_cookies
            })
        if contains_keywords(request_url):
            issues.append({
                'type': 'URL',
                'url': request_url,
                'content': request_url
            })
    return issues

def contains_keywords(text):
    """Check if the text contains any of the specified keywords."""
    for keyword in keywords:
        if re.search(r'\b' + keyword + r'\b', text, re.IGNORECASE):
            return True
    return False

def scan_entire_har(har_content):
    """Scan the entire HAR content for security issues."""
    lines = har_content.split('\n')
    issues = []
    for line in lines:
        for keyword in keywords:
            if re.search(r'\b' + keyword + r'\b', line, re.IGNORECASE):
                issues.append({
                    'type': 'General',
                    'content': f"Security Concern: The following content might contain {keyword}.\n{line}"
                })
                break
    return issues

def create_timing_plot(entries):
    """Create timing plot using Plotly."""
    df = pd.DataFrame(entries)
    fig = px.timeline(df, x_start="startedDateTime", x_end="endDateTime", y="request_url", color="response_status")
    fig.update_layout(title='Request Timing', xaxis_title='Time', yaxis_title='URL')
    return pio.to_html(fig, full_html=False)

def compare_hars(har1_content, har2_content):
    """Compare two HAR files."""
    har1_entries = parse_har(har1_content)
    har2_entries = parse_har(har2_content)
    
    metrics1 = generate_metrics(har1_entries)
    metrics2 = generate_metrics(har2_entries)

    timing_plot1 = create_timing_plot(har1_entries)
    timing_plot2 = create_timing_plot(har2_entries)

    comparison = {
        'total_entries_diff': metrics1['total_entries'] - metrics2['total_entries'],
        'total_time_diff': metrics1['total_time'] - metrics2['total_time'],
        'average_time_diff': metrics1['average_time'] - metrics2['average_time'],
        'status_codes_diff': {}
    }
    
    all_statuses = set(metrics1['status_codes'].keys()).union(set(metrics2['status_codes'].keys()))
    for status in all_statuses:
        count1 = metrics1['status_codes'].get(status, 0)
        count2 = metrics2['status_codes'].get(status, 0)
        comparison['status_codes_diff'][status] = count1 - count2

    security_issues1 = check_security_issues(har1_entries)
    security_issues2 = check_security_issues(har2_entries)

    return {
        'metrics1': metrics1,
        'metrics2': metrics2,
        'comparison': comparison,
        'timing_plot1': timing_plot1,
        'timing_plot2': timing_plot2,
        'security_issues1': security_issues1,
        'security_issues2': security_issues2
    }

@app.route('/', methods=['GET', 'POST'])
def index():
    """Handle the main page requests."""
    if request.method == 'POST':
        har_content = None
        if 'har_file' in request.files and request.files['har_file'].filename != '':
            har_file = request.files['har_file']
            har_content = har_file.read().decode('utf-8')
        elif 'har_text' in request.form and request.form['har_text'].strip() != '':
            har_content = request.form['har_text']

        if har_content:
            try:
                entries = parse_har(har_content)
                metrics = generate_metrics(entries)
                security_issues = check_security_issues(entries)
                general_issues = scan_entire_har(har_content)
                timing_plot = create_timing_plot(entries)
                return render_template('index.html', entries=entries, metrics=metrics, security_issues=security_issues, general_issues=general_issues, timing_plot=timing_plot)
            except Exception as e:
                print(f"Error parsing HAR content: {e}")
                return render_template('index.html', error=f"Error parsing HAR content: {e}")

    return render_template('index.html')

@app.route('/compare', methods=['GET', 'POST'])
def compare():
    """Handle the comparison page requests."""
    if request.method == 'POST':
        har1_content = None
        har2_content = None
        
        if 'har1_file' in request.files and request.files['har1_file'].filename != '' and 'har2_file' in request.files and request.files['har2_file'].filename != '':
            har1_file = request.files['har1_file']
            har2_file = request.files['har2_file']
            har1_content = har1_file.read().decode('utf-8')
            har2_content = har2_file.read().decode('utf-8')
        elif 'har1_text' in request.form and request.form['har1_text'].strip() != '' and 'har2_text' in request.form and request.form['har2_text'].strip() != '':
            har1_content = request.form['har1_text']
            har2_content = request.form['har2_text']

        if har1_content and har2_content:
            try:
                comparison_results = compare_hars(har1_content, har2_content)
                return render_template('compare.html', comparison_results=comparison_results)
            except Exception as e:
                print(f"Error comparing HAR content: {e}")
                return render_template('compare.html', error=f"Error comparing HAR content: {e}")

    return render_template('compare.html')

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
