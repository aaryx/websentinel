from websentinel.models import Response


def make_response(url="https://example.com/", status=200, headers=None,
                  cookies=(), body="", ctype="text/html"):
    h = {k.lower(): v for k, v in (headers or {}).items()}
    return Response(url=url, final_url=url, status=status, headers=h,
                    set_cookies=list(cookies), body=body,
                    content_type=ctype or h.get("content-type", ""),
                    content_length=len(body), elapsed_ms=1.0,
                    http_version="HTTP/2")
