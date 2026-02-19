import sys
from web.app import create_app, db
from web.models import User

def create_admin(username, password):
    app = create_app()
    with app.app_context():
        existing = User.query.filter_by(username=username).first()
        if existing:
            print(f"❌ Error: User '{username}' already exists.")
            return
        
        # Create new admin
        user = User(username=username, email=f"{username}@shieldx.admin", role="admin")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f"✅ Success! Admin account '{username}' created.")
        print(f"👉 Login at: http://localhost:5000/login")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python create_admin.py <username> <password>")
        print("Example: python create_admin.py admin 123456")
    else:
        create_admin(sys.argv[1], sys.argv[2])
