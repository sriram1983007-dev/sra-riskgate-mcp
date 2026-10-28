FROM python:3.12-slim
RUN pip install --no-cache-dir "sra-riskgate-mcp==0.9.1"
ENTRYPOINT ["sra-riskgate-mcp"]
