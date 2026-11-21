"""PDF output, built by rendering the same HTML used for --html and
converting it with weasyprint. Kept as a separate optional import so the
core tool has no PDF dependency unless you actually ask for one."""


def html_to_pdf(html_string, out_path):
    from weasyprint import HTML  # imported lazily -- optional dependency
    HTML(string=html_string).write_pdf(out_path)
