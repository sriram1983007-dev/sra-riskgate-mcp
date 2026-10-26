FROM python:3.12-slim
RUN pip install --no-cache-dir "sra-riskgate-mcp==0.7.2"
ENTRYPOINT ["sra-riskgate-mcp"]
