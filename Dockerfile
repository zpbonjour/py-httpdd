# Super basic Dockerfile to run this as a container.
FROM public.ecr.aws/lambda/python:latest

COPY lambda_handler.py .

RUN pip install requests boto3

CMD ["lambda_handler.lambda_handler"]
