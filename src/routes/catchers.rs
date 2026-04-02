use rocket::{Request, catch, response::content::RawHtml};

const NOT_FOUND_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>404 - Annie Mei</title>
<link rel="icon" type="image/png" href="/static/favicon.png">
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{
    min-height:100vh;
    display:flex;align-items:center;justify-content:center;
    background:linear-gradient(145deg,#0f0f13 0%,#1a1a2e 100%);
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
    color:#e4e4e7;
    padding:1rem;
  }
  .card{
    width:100%;max-width:420px;
    background:rgba(255,255,255,0.04);
    border:1px solid rgba(255,255,255,0.08);
    border-radius:16px;
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    box-shadow:0 8px 32px rgba(0,0,0,0.3);
    padding:2.5rem 2rem;
    text-align:center;
    animation:fadeSlideIn .5s ease-out;
  }
  .status{
    font-size:4rem;font-weight:700;
    color:#a78bfa;
    margin-bottom:.5rem;
    animation:scaleIn .4s ease-out .15s both;
  }
  h1{
    font-size:1.375rem;font-weight:600;
    color:#a78bfa;
    margin-bottom:.75rem;
  }
  .message{
    font-size:.9375rem;line-height:1.6;
    color:#a1a1aa;
    margin-bottom:1.5rem;
  }
  .brand{
    margin-top:2rem;
    font-size:.75rem;
    color:#3f3f46;
    letter-spacing:.04em;
  }
  @keyframes fadeSlideIn{
    from{opacity:0;transform:translateY(12px)}
    to{opacity:1;transform:translateY(0)}
  }
  @keyframes scaleIn{
    from{opacity:0;transform:scale(.6)}
    to{opacity:1;transform:scale(1)}
  }
</style>
</head>
<body>
  <div class="card">
    <p class="status">404</p>
    <h1>Page Not Found</h1>
    <p class="message">There's nothing here. If you're trying to link your AniList account, start from the bot command in Discord.</p>
    <p class="brand">Annie Mei</p>
  </div>
</body>
</html>"#;

#[catch(404)]
pub fn not_found(_req: &Request) -> RawHtml<&'static str> {
    RawHtml(NOT_FOUND_HTML)
}
