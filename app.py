from flask import Flask, render_template, request, redirect, session, Response
import sqlite3
import csv
import io

app = Flask(__name__)
app.secret_key = "secureaccess123"

DATABASE = "access.db"


# DATABASE CREATION
def create_database():
    conn = sqlite3.connect(DATABASE)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            username TEXT,
            role TEXT,
            resource TEXT,
            risk INTEGER,
            decision TEXT
        )
    """)

    conn.commit()
    conn.close()


# LOGIN
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == "admin" and password == "admin123":
            session["username"] = username
            return redirect("/dashboard")

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


# DASHBOARD
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect("/")

    result = None
    explanation = None

    if request.method == "POST":
        role = request.form.get("role")
        resource = request.form.get("resource")

        try:
            risk = int(request.form.get("risk"))
        except (TypeError, ValueError):
            return render_template(
                "index.html",
                result="INVALID INPUT",
                explanation="Enter a valid risk score."
            )

        if risk < 0 or risk > 100:
            return render_template(
                "index.html",
                result="INVALID INPUT",
                explanation="Risk score must be between 0 and 100."
            )

        # ROLE-BASED ACCESS CONTROL
        if role == "Admin":
            allowed = True
        elif role == "Manager" and resource != "User Data":
            allowed = True
        elif role == "Employee" and resource == "Dashboard":
            allowed = True
        else:
            allowed = False

        # RISK-BASED AUTHORIZATION
        if risk >= 70:
            allowed = False
            explanation = "High risk detected. Access blocked."
        elif allowed:
            explanation = "Access allowed. Role permissions and risk level are acceptable."
        else:
            explanation = "Your role does not have permission for this resource."

        result = "ACCESS GRANTED" if allowed else "ACCESS DENIED"

        # SAVE HISTORY
        conn = sqlite3.connect(DATABASE)

        conn.execute(
            """INSERT INTO history
            (username, role, resource, risk, decision)
            VALUES (?, ?, ?, ?, ?)""",
            (session["username"], role, resource, risk, result)
        )

        conn.commit()
        conn.close()

    return render_template(
        "index.html",
        result=result,
        explanation=explanation
    )


# ACCESS HISTORY
@app.route("/history")
def history():
    if "username" not in session:
        return redirect("/")

    conn = sqlite3.connect(DATABASE)

    records = conn.execute(
        "SELECT * FROM history ORDER BY rowid DESC"
    ).fetchall()

    conn.close()

    return render_template("history.html", history=records)


# ANALYTICS
@app.route("/analytics")
def analytics():
    if "username" not in session:
        return redirect("/")

    conn = sqlite3.connect(DATABASE)

    total = conn.execute(
        "SELECT COUNT(*) FROM history"
    ).fetchone()[0]

    granted = conn.execute(
        "SELECT COUNT(*) FROM history WHERE decision=?",
        ("ACCESS GRANTED",)
    ).fetchone()[0]

    denied = conn.execute(
        "SELECT COUNT(*) FROM history WHERE decision=?",
        ("ACCESS DENIED",)
    ).fetchone()[0]

    low = conn.execute(
        "SELECT COUNT(*) FROM history WHERE risk < 40"
    ).fetchone()[0]

    medium = conn.execute(
        "SELECT COUNT(*) FROM history WHERE risk >= 40 AND risk < 70"
    ).fetchone()[0]

    high = conn.execute(
        "SELECT COUNT(*) FROM history WHERE risk >= 70"
    ).fetchone()[0]

    conn.close()

    return render_template(
        "analytics.html",
        total=total,
        granted=granted,
        denied=denied,
        low=low,
        medium=medium,
        high=high
    )


# CSV DOWNLOAD
@app.route("/download-history")
def download_history():
    if "username" not in session:
        return redirect("/")

    conn = sqlite3.connect(DATABASE)

    records = conn.execute(
        "SELECT * FROM history ORDER BY rowid DESC"
    ).fetchall()

    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Username",
        "Role",
        "Resource",
        "Risk Score",
        "Decision"
    ])

    writer.writerows(records)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=access_history.csv"
        }
    )


# USER MANAGEMENT
@app.route("/users")
def users():
    if "username" not in session:
        return redirect("/")

    return render_template("users.html")


# POLICY MANAGEMENT
@app.route("/policy")
def policy():
    if "username" not in session:
        return redirect("/")

    return render_template("policy.html")


# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# RUN APPLICATION
if __name__ == "__main__":
    create_database()
    app.run(debug=True, port=5001)