   FROM python:3.12-slim
   RUN pip install --no-cache-dir "sra-riskgate-mcp==0.1.0"
   ENTRYPOINT ["sra-riskgate-mcp"]
