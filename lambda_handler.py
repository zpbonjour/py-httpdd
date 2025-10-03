

"""
AWS Lambda function for invoking HTTP requests and logging results to Datadog.

This script implements a generic HTTP invoker as an AWS Lambda function. The
`lambda_handler` function receives an event payload specifying the details of an
HTTP request (URL, method, headers, payload, etc.). It executes the request,
measures its performance, and sends a structured log of the transaction to
Datadog using the `send_to_datadog` helper function.

The script is designed to be flexible, supporting various request configurations,
SSL validation control, and different response formats, including a format
compatible with AWS API Gateway. It also handles Lambda warmup events gracefully.

Functions:
    lambda_handler(event, context): The main entry point for the Lambda. Parses
        the event, executes the HTTP request, and logs the outcome.
    send_to_datadog(input_log): Fetches the Datadog API key from an environment
        variable and sends a log payload to the Datadog HTTP Logs Intake API.

ENV Configuration:
    DD_API_KEY (str): A module-level constant specifying the environment variable
    that holds the Datadog API key.
    DD_API_ENDPOINT (str, optional): The Datadog logs intake endpoint.
"""
# pylint: disable=broad-exception-caught
# pylint: disable=line-too-long
import json
import sys
import os
import base64
import logging
import requests
import traceback

dd_endpoint = os.environ.get("DD_API_ENDPOINT", "https://http-intake.logs.datadoghq.com/api/v2/logs") # Datadog logs intake endpoint, defaults to US site

# Datadog Tags
ddsource = os.environ.get("DD_SOURCE", "lambda") # Set the DD source tag, defaults to "lambda"
service = os.environ.get("DD_SERVICE", "http_invoker_lambda") # Set the DD service tag, defaults to "http_invoker_lambda"
ddtags = os.environ.get("DD_TAGS", "environment:development") # Set the DD tags, defaults to "environment:development"

logger = logging.getLogger()
logger.setLevel(logging.INFO) # Set the default logging level to INFO, or DEBUG if needed.


# Handler for stdout (INFO and debug if debug is enabled)
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.INFO)
stdout_handler.addFilter(lambda record: record.levelno <= logging.INFO)
stdout_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
stdout_handler.setFormatter(stdout_formatter)

# Handler for stderr (WARNING and higher)
stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.WARNING)
stderr_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
stderr_handler.setFormatter(stderr_formatter)

# Remove default handlers and the above custom handlers
logger.handlers = []
logger.addHandler(stdout_handler)
logger.addHandler(stderr_handler)

def lambda_handler(event, context) -> dict | bool:
    """
    Invokes an HTTP request based on parameters from the Lambda event.

    This function serves as a generic HTTP client within a Lambda environment.
    It parses an input `event` for request details (URL, method, payload, etc.),
    executes the request, logs the transaction to Datadog, and can return a
    structured response. It also handles Lambda warm-up events by exiting early.

    Args:
        event (dict): The event dictionary from AWS Lambda. Expected keys include:
            - 'url' (str): The target URL for the HTTP request. Required.
            - 'method' (str, optional): HTTP method (e.g., 'GET', 'POST').
              Defaults to 'GET'.
            - 'payload' (str | dict | None, optional): Request body. Defaults to None.
            - 'headers' (dict, optional): HTTP headers. Defaults to {}.
            - 'log_return_body' (bool, optional): If True, the response body is
              returned (base64-encoded). Requires 'http_response_enabled'.
              Defaults to False.
            - 'http_response_enabled' (bool, optional): If True, returns a
              structured HTTP response for API Gateway. Defaults to False.
            - 'validate_ssl' (bool, optional): Whether to verify SSL certificates.
              Defaults to True.
            - 'allow_redirects' (bool, optional): Whether to follow HTTP redirects.
              Defaults to True.
            - 'http_timeout' (int | str, optional): Request timeout in seconds.
              Defaults to 10.
            - 'type'/'subType' (str, optional): Used for warmup detection.
            - 'send_dd_logs' (bool, optional): If False, skips sending logs to Datadog.
              Defaults to True.

        context (object): The AWS Lambda context object, providing runtime info
            like ARN and request ID for logging.

    Raises:
        ValueError: If 'url' is missing, invalid, or if 'return_body' is True
            while 'http_response_enabled' is False.
        requests.exceptions.RequestException: For issues during the HTTP request
            to the target URL (e.g., connection errors, timeouts).
        Exception: For other unexpected errors during request execution.
        The function will also propagate exceptions from `send_to_datadog`, such
        as `KeyError` if 'DD_API_KEY' is not set.

    Returns:
        dict | bool:
        - A dictionary formatted for API Gateway if 'http_response_enabled' is True.
        - A boolean `True` for successful warmup events or standard invocations
          where 'http_response_enabled' is False.
    """
    if event.get('Action') == 'LAMBDA_WARMUP':
        logger.info("Warmup event detected, no action taken.")
        return True

    # Extract parameters from the event
    url = event.get('url') # Required, protocol must be http or https
    method = event.get('method', 'GET').upper() # Default to GET if not provided
    payload = event.get('payload', None) # Can be None, string, or stringified JSON, default to None
    headers = event.get('headers', {}) # if payload is JSON, Content-Type will automatically be set to 'application/json', default to empty dict
    log_return_body = event.get('return_body', False) # Whether to return and log the response body (base64-encoded) or not, requires http_response_enabled be True, default to False
    http_response_enabled = event.get('http_response_enabled', False) # For use with API Gateway, default to False
    validate_ssl = event.get('validate_ssl', True) # Validate SSL certificates or not, default to True
    allow_redirects = event.get('allow_redirects', True) # Allow redirects or not, default to True
    http_timeout = event.get('http_timeout', 10) # string or int, Timeout for the HTTP request in seconds, default to 10 seconds
    send_dd_logs = event.get('send_dd_logs', True) # Whether to send logs to Datadog or not, default to True

    log_payload = {
        "http": {
            "url": url,
            "method": method,
            "useragent": headers.get('User-Agent', 'HttpInvokerLambda/1.0'),
            #"status_code": "",
            "url_details": {
                "host": url.split('/')[2] if len(url.split('/')) > 2 else "Unknown",
                "port": url.split('/')[2].split(':')[1] if ':' in url.split('/')[2] else ("443" if url.startswith('https://') else "80"),
                "path": '/' + '/'.join(url.split('/')[3:]) if len(url.split('/')) > 3 else "/",
                "queryString": url.split('?')[1] if '?' in url else "",
                "scheme": str(url.split(':')[0] if ':' in url else "Unknown").upper()
            }
        },
        #"message": "",
        #"duration": "",
        "ddsource": ddsource,
        "service": service,
        "ddtags": ddtags,
        "lambda_arn_or_name": context.get('invoked_function_arn') if context else context.function_name,
        "aws_request_id": context.get('aws_request_id') if context else "Unknonwn"
    }

    # Fail if required parameters are missing or invalid
    try:
        if not url:
            log_payload.setdefault('error', {})['message'] = "The 'url' parameter is required."
            del log_payload['http']['url_details']
            raise ValueError("The 'url' parameter is required.")

        if not url.startswith(('http://', 'https://')):
            log_payload.setdefault('error', {})['message'] = "The 'url' parameter must start with 'http://' or 'https://'."
            del log_payload['http']['url_details']
            raise ValueError("The 'url' parameter must start with 'http://' or 'https://'.")

        if log_return_body and not http_response_enabled:
            log_payload.setdefault('error', {})['message'] = "The 'return_body' parameter can only be True if 'http_response_enabled' is also True."
            raise ValueError("The 'return_body' parameter can only be True if 'http_response_enabled' is also True.")

    except ValueError as precheck_error:
        logger.error(str(precheck_error).replace('\n',' || '))
        log_payload['error']['kind'] = type(precheck_error).__name__
        log_payload['error']['stack'] = traceback.format_exc()
        log_payload["status"] = "error"
        send_to_datadog(input_log=log_payload)
        raise ValueError(str(precheck_error)) from None


    # Prepare request arguments
    request_args = {
        'url': url,
        'method': method,
        'timeout': int(http_timeout),
        'headers': headers,
        'verify': validate_ssl,
        'allow_redirects': allow_redirects
    }

    # Attempt to convert payload to Dict if it's escaped JSON, update headers accordingly
    if payload:
        try:
            payload = json.loads(payload)  # Try to parse payload as JSON
        except (json.decoder.JSONDecodeError, TypeError):
            pass  # If it fails, keep it as is (string or other type)
        if isinstance(payload, (dict, list)):
            request_args['json'] = payload
            headers['Content-Type'] = 'application/json'
        else:
            request_args['data'] = payload
            headers['Content-Type'] = 'text/plain'

    try:
        # Make the HTTP request and measure the time
        response = requests.request(**request_args)
        response_time_ms = response.elapsed.total_seconds() * 1000  # in milliseconds
        response_time_ns = response.elapsed.total_seconds() * 1000000000  # in nanoseconds
        message = f"HTTP {method} to {url} returned {response.status_code} in {response_time_ms:.2f} ms"
        log_payload['message'] = message
        log_payload['http']['status_code'] = response.status_code
        log_payload['duration'] = int(response_time_ns)
        if str(response.status_code).startswith('2'):
            log_payload["status"] = "info"
        if str(response.status_code).startswith('3'):
            log_payload["status"] = "warn"
        if str(response.status_code).startswith('4') or str(response.status_code).startswith('5'):
            log_payload["status"] = "error"
    except requests.exceptions.RequestException as requests_error:
        logger.error(f"HTTP {method} to {url} failed: %s", str(requests_error).replace('\n',' || '))
        log_payload.setdefault('error', {})['kind'] = type(requests_error).__name__
        log_payload['error']['stack'] = traceback.format_exc()
        log_payload['error']['message'] = str(requests_error)
        log_payload['message'] = str(requests_error)
        log_payload["status"] = "error"
        send_to_datadog(input_log=log_payload)
        raise requests.exceptions.RequestException(str(requests_error)) from None
    except Exception as requests_error:
        logger.error(f"An unexpected error occurred while using method '{method}' to '{url}': %s", str(requests_error).replace('\n',' || '))
        log_payload.setdefault('error', {})['kind'] = type(requests_error).__name__
        log_payload['error']['stack'] = traceback.format_exc()
        log_payload['error']['message'] = str(requests_error)
        log_payload['message'] = str(requests_error)
        log_payload["status"] = "error"
        send_to_datadog(input_log=log_payload)
        raise Exception(str(requests_error)) from None


    if log_return_body:
        base64_encoded_response_data = base64.b64encode(response.content).decode('utf-8')
        log_payload['base64_encoded_response_data'] = base64_encoded_response_data
    else:
        base64_encoded_response_data = None


    send_to_datadog(input_log=log_payload)

    if http_response_enabled:
        response_body = {
            'url': url,
            'method': method,
            'response_code': response.status_code,
            'base64_encoded_response_data': base64_encoded_response_data,
            'response_time_ms': response_time_ms
        }
        return {
            'isBase64Encoded': False,
            'statusCode': 200 if not log_payload['error'] else 500,
            'headers': {
                'Content-Type': 'application/json' if log_return_body else 'text/plain'
        },
        'body': json.dumps(response_body) if log_return_body else ''
        }
    return True




def send_to_datadog(input_log:dict) -> bool:
    """
    Sends a log entry to Datadog via the HTTP Logs Intake API.

    Args:
        input_log (dict): The log entry to send to Datadog, formatted as a dictionary.

    Returns:
        bool: True if the log was sent successfully, False otherwise.

    Raises:
        ValueError: If the DD_API_KEY environment variable is not set.

    Logs:
        Errors encountered during the request are logged using the logger.
    """
    try:
        # Fetch the DataDog API Key from environment
        api_key = os.environ['DD_API_KEY']
    except KeyError:
        logger.error("Failed to fetch environment variable DATADOG_API_KEY")
        raise

    # Datadog logs intake endpoint

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'DD-API-KEY': api_key,
    }

    try:
        response = requests.post(dd_endpoint, json=input_log, headers=headers, timeout=30)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as dd_error:
        logger.error("Error sending log to Datadog: %s", str(dd_error).replace('\n',' || '))
        raise
