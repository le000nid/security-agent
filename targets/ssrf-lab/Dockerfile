FROM python:3.11.14-slim-bookworm
WORKDIR /lab
COPY server.py ./server.py
USER 1000:1000
EXPOSE 3000
CMD ["python", "server.py"]
