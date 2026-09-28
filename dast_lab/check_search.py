import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen
from datetime import datetime, timezone
from pathlib import Path


def search_products(query):
    params = urlencode({"q": query})
    url = f"http://localhost:3000/rest/products/search?{params}"

    try:
        with urlopen(url, timeout=5) as response:
            status = response.status
            body = response.read().decode("utf-8", errors="replace")
    except HTTPError as error:
        # Сервер ответил, но код ответа означает ошибку.
        status = error.code
        body = error.read().decode("utf-8", errors="replace")
        error.close()
    except (URLError, TimeoutError, OSError) as error:
        # Ответ не получили: например, сервер недоступен.
        return {
            "query": query,
            "http_status": None,
            "network_error": str(error),
        }

    product_count = None

    try:
        data = json.loads(body)
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            product_count = len(data["data"])
    except json.JSONDecodeError:
        # Ответ может быть HTML-страницей ошибки вместо JSON.
        pass

    return {
        "query": query,
        "http_status": status,
        "product_count": product_count,
        "sqlite_error": "SQLITE_ERROR" in body,
    }


def main():
    queries = [
        "apple",
        "zzzz_no_such_product_762",
        "apple'",
        "apple''",
    ]

    results = [search_products(query) for query in queries]

    for result in results:
        print(json.dumps(result, ensure_ascii=False))

    baseline, missing, single_quote, double_quote = results

    controls_ok = (
        baseline["http_status"] == 200
        and (baseline.get("product_count") or 0) > 0
        and missing["http_status"] == 200
        and missing.get("product_count") == 0
    )

    error_disclosed = any(
        result.get("sqlite_error", False) for result in results
    )

    suspicious_pattern = (
        controls_ok
        and single_quote["http_status"] == 500
        and single_quote.get("sqlite_error", False)
        and double_quote["http_status"] == 200
        and double_quote.get("product_count") == 0
    )

    report = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "target": "http://localhost:3000/rest/products/search",
        "controls_ok": controls_ok,
        "sqlite_error_disclosed": error_disclosed,
        "sql_injection_suspected": suspicious_pattern,
        "sql_injection_confirmed": False,
        "results": results,
    }

    output = Path(__file__).resolve().parent / "search_report.json"
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"\nКонтрольные проверки прошли: {controls_ok}")
    print(f"Раскрыта ошибка SQLite: {error_disclosed}")
    print(f"Признаки SQL-инъекции: {suspicious_pattern}")
    print(f"Отчёт сохранён: {output}")
    
if __name__ == "__main__":
    main()