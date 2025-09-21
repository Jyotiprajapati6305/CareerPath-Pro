from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import google.generativeai as genai
import os
from werkzeug.utils import secure_filename
import PyPDF2
import docx
from PIL import Image
import pytesseract
from pdf2image import convert_from_path
import google.generativeai as genai

import json
import datetime
from linkedin_scraper import fetch_linkedin_jobs
import re
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash, check_password_hash

# ------------------------
# App Config
# ------------------------

app = Flask(__name__)
app.secret_key = "supersecretkey"  # ⚠️ Cha nge in production
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# Upload folder setup
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Jyoti%40123@localhost:5432/app'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)

# ------------------------
# Flask-Login Setup
# ------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ------------------------
# Models
# ------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(10), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    assessments = db.relationship("Assessment", backref="user", lazy=True)

    def __repr__(self):
        return f"<User {self.first_name} {self.last_name} - {self.email}>"

class Assessment(db.Model):
    __tablename__ = "assessment"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    domain = db.Column(db.String(100), default="General")
    scores = db.Column(db.Text, nullable=False)  # raw answers
    category_scores = db.Column(db.Text, nullable=False)  # formatted text
    insights = db.Column(db.Text, nullable=False)  # raw insights JSON
    avg_score = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ------------------------
# Resume Model
# ------------------------
class Resume(db.Model):
    __tablename__ = "resume"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    user = db.relationship("User", backref=db.backref("resumes", lazy=True))
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------------
# Google Gemini Setup
# ------------------------
NUM_QUESTIONS = 10
genai.configure(api_key="AIzaSyAlFXGGzxuDYbB_JIe7EHPbtzUJKgTVVys")  # Replace with your key
CATEGORIES = ["Creativity", "Public Speaking","Mathemetics","Leadership","Management"]
QUESTION_CATEGORY_MAP = {i: i % len(CATEGORIES) for i in range(NUM_QUESTIONS)}

# ------------------------
# Helpers
# ------------------------

def generate_questions(domain="General", num_questions=NUM_QUESTIONS):
    """
    Ask the model for `num_questions` concise self-assessment questions.
    Returns a list of exactly `num_questions` strings (pads with fallbacks if needed).
    """
    model = genai.GenerativeModel("gemini-2.5-flash")
    prompt = (
        f"Generate {num_questions} concise self-assessment questions for the domain '{domain}'.\n"
        "Return each question on a new line and provide only the question text (no numbering or extra commentary)."
    )
    response = model.generate_content(prompt)
    raw = (response.text or "").strip()

    # clean up lines (remove leading numbering/bullet characters)
    lines = []
    for line in raw.splitlines():
        line = re.sub(r'^[\s\-\•\d\.\)\(]+', '', line).strip()
        if line:
            lines.append(line)

    # keep only reasonable lines
    questions = [q for q in lines if len(q) > 5]

    # Fallback: if model returned fewer than requested, generate reasonable template questions to fill up
    if len(questions) < num_questions:
        needed = num_questions - len(questions)
        fallback = []
        for i in range(needed):
            cat = CATEGORIES[(len(questions) + i) % len(CATEGORIES)]
            fallback.append(f"How confident are you in your {cat.lower()} skills?")
        questions.extend(fallback)

    return questions[:num_questions]

# def generate_questions(domain="General"):
#     model = genai.GenerativeModel("gemini-2.5-flash")
#     prompt = f"Generate 15 self-assessment questions for the domain '{domain}'. Only return the question text."
#     response = model.generate_content(prompt)
#     questions = [q.strip("•-1234567890.() ") for q in response.text.strip().split("\n") if q.strip()]
#     return questions[:10]

def generate_career_suggestions(answers, domain="General"):
    model = genai.GenerativeModel("gemini-2.5-flash")
    prompt = f"A student answered: {answers}. Suggest career paths, skills, next steps for domain in summarise and 2 3 line only'{domain}'."
    return model.generate_content(prompt).text

def generate_dynamic_insights(category_scores):
    model = genai.GenerativeModel("gemini-2.5-flash")
    prompt = f"Student scores: {category_scores}. Return JSON with labels and suggestions."
    response = model.generate_content(prompt)
    try:
        return json.loads(response.text)
    except:
        # fallback
        insights = {}
        for cat, score in category_scores.items():
            if score >= 4:
                insights[cat] = ["Strong", "🚀 Keep building advanced projects."]
            elif score >= 3:
                insights[cat] = ["Average", "📘 Take intermediate courses."]
            else:
                insights[cat] = ["Needs Improvement", "💡 Focus on basics."]
        return insights
def format_assessment_results(category_scores, insights):
    formatted = []
    for cat, score in category_scores.items():
        label, suggestion = insights.get(cat, ["N/A", "No suggestion"])
        formatted.append(f"{cat} — {label} ({score*100:.0f}%)\n💡 Suggestion: {suggestion}")
    return "\n\n".join(formatted)

# ------------------------
# Routes
# ------------------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch user-specific assessment data
    user_results = Assessment.query.filter_by(user_id=current_user.id).first()
    
    # Example structure: { 'Technical': 80, 'Marketing': 60, 'Design': 40 }
    results = {}
    if user_results:
        # Assuming you store data as JSON or separate columns
        results = user_results.scores  # e.g., JSON: {"Technical":80, "Marketing":60, ...}

    return render_template('index.html', assessment_results=results)
# ------------------------
# Assessment Routes
# ------------------------
@app.route("/assessment", methods=["GET", "POST"])
@login_required
def assessment():
    if request.method == "POST":
        # ensure we read answers in order q1..qN
        answers = []
        for i in range(1, NUM_QUESTIONS + 1):
            val = request.form.get(f"q{i}")
            if val is None:
                flash("Please answer all questions.", "danger")
                return redirect(url_for("assessment"))
            try:
                answers.append(int(val))
            except ValueError:
                flash("Please provide numeric values for all questions.", "danger")
                return redirect(url_for("assessment"))

        # 2️⃣ Calculate category-wise scores
        category_totals = {cat: [] for cat in CATEGORIES}
        for idx, ans in enumerate(answers):
            cat_index = QUESTION_CATEGORY_MAP.get(idx, 0)
            cat = CATEGORIES[cat_index]
            category_totals[cat].append(ans)

        category_scores = {cat: (sum(vals)/len(vals) if vals else 0) for cat, vals in category_totals.items()}

        # 3️⃣ Generate insights
        insights = generate_dynamic_insights(category_scores)

        # 4️⃣ Calculate average score
        avg_score = sum(answers) / len(answers)

        # 5️⃣ Store in database
        try:
            new_assessment = Assessment(
                user_id=current_user.id,
                domain=request.args.get("domain", "General"),
                scores=json.dumps(answers),
                category_scores=json.dumps(category_scores),
                insights=json.dumps(insights),
                avg_score=avg_score
            )
            db.session.add(new_assessment)
            db.session.commit()
            flash("Assessment saved successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error saving assessment: {str(e)}", "danger")
            return redirect(url_for("assessment"))

        # 6️⃣ Render results
        return render_template("results.html", scores=answers, category_scores=category_scores, avg=avg_score, insights=insights)

    # GET request: generate questions (now requests NUM_QUESTIONS)
    domain = request.args.get("domain", "General")
    questions = generate_questions(domain, NUM_QUESTIONS)
    return render_template("assessment.html", questions=questions, domain=domain)


@app.route("/my_assessments")
@login_required
def my_assessments():
    assessments = Assessment.query.filter_by(user_id=current_user.id).order_by(Assessment.created_at.desc()).all()
    return render_template("my_assessments.html", assessments=assessments)

# ------------------------
# Skills
# ------------------------
@app.route("/skills", methods=["GET","POST"])
@login_required
def skills():
    ai_suggestions, questions = None, []
    domain = request.form.get("domain") or request.args.get("domain") or "General"

    # Generate domain-specific questions dynamically
    questions = generate_questions(domain)  # AI-powered, dynamic questions

    if request.method=="POST":
        answers = {k:v for k,v in request.form.items() if k.startswith("q")}
        if answers:
            ai_suggestions = generate_career_suggestions(answers, domain)

    return render_template("skills.html", ai_suggestions=ai_suggestions, questions=questions, selected_domain=domain)
@app.route("/skills/questions")
@login_required
def skills_questions():
    domain = request.args.get("domain", "General")
    try:
        questions = generate_questions(domain)
        return {"questions": questions}  # JSON response
    except Exception as e:
        print(f"[Error generating questions]: {e}")
        return {"questions": []}, 500

# ------------------------
# Jobs
# ------------------------
@app.route("/jobs", methods=["GET", "POST"])
@login_required
def jobs():
    search_query = ""
    search_location = ""
    ai_recommendation = []
    jobs_data = []

    # Optional: set default max jobs to fetch
    MAX_JOBS = 20
    LINKEDIN_TOKEN = "WPL_AP1.rcR3rAALewpIb6id.OcUjOw=="  # Replace if needed

    if request.method == "POST":
        # Get user input
        search_query = request.form.get("interest", "").strip()
        search_location = request.form.get("location", "").strip()

        if search_query and search_location:
            try:
                # Fetch LinkedIn jobs with scrolling
                jobs_data = fetch_linkedin_jobs(
                    query=search_query,
                    location=search_location,
                    max_results=MAX_JOBS
                )
            except Exception as e:
                print(f"[Error fetching LinkedIn jobs]: {e}")
                jobs_data = []

            try:
                # Generate AI career suggestions
                model = genai.GenerativeModel("gemini-2.5-flash")
                prompt = (
                    f"Give 8 concise career suggestions for '{search_query}' in "
                    f"'{search_location}', each as a bullet point, properly formatted."
                )
                ai_text = model.generate_content(prompt).text

                # Convert AI text to list of bullet points
                ai_recommendation = [
                    line.strip(" -•") for line in ai_text.split("\n") if line.strip()
                ]
            except Exception as e:
                print(f"[Error generating AI recommendations]: {e}")
                ai_recommendation = []

    return render_template(
        "jobs.html",
        jobs=jobs_data,
        search_query=search_query,
        search_location=search_location,
        ai_recommendation=ai_recommendation
    )

# ------------------------
# Resume
# ------------------------

@app.route("/resume", methods=["GET", "POST"])
@login_required
def resume():
    ai_result_list = []      # AI resume analysis suggestions
    jobs_data = []           # Real-time LinkedIn jobs
    error_message = None
    tutorial_tips = None
    content = ""             # Extracted resume text

    if request.method == "POST":
        file = request.files.get("resume_file")
        get_tips = request.form.get("get_tips")  # Resume tips button

        if file and file.filename != "":
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

            # ----------------- Store resume in DB -----------------
            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
                new_resume = Resume(
                    user_id=current_user.id,
                    filename=filename,
                    file_data=file_data
                )
                db.session.add(new_resume)
                db.session.commit()
                flash("Resume uploaded and saved successfully!", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"Error saving resume in database: {str(e)}", "danger")

            ext = filename.split('.')[-1].lower()
            content = ""

            try:
                # ------------------ PDF ------------------
                if ext == "pdf":
                    pdf_reader = PyPDF2.PdfReader(file_path)
                    for page in pdf_reader.pages:
                        text = page.extract_text()
                        if text and text.strip():
                            content += text + "\n"

                    # Fallback for scanned PDFs
                    if not content.strip():
                        images = convert_from_path(file_path)
                        for img in images:
                            content += pytesseract.image_to_string(img) + "\n"

                # ------------------ DOC / DOCX ------------------
                elif ext in ["doc", "docx"]:
                    doc_file = docx.Document(file_path)
                    content = "\n".join([para.text for para in doc_file.paragraphs if para.text.strip()])

                # ------------------ IMAGE ------------------
                elif ext in ["jpg", "jpeg", "png"]:
                    img = Image.open(file_path)
                    content = pytesseract.image_to_string(img)

                else:
                    error_message = "Unsupported file type."

                content = re.sub(r'\n+', '\n', content).strip()
                if not content and not error_message:
                    error_message = "No readable text found in the resume."

            except Exception as e:
                error_message = f"Error processing file: {str(e)}"

            # ----------------- AI Resume Analysis -----------------
            if content and not error_message:
                try:
                    model = genai.GenerativeModel("gemini-2.5-flash")
                    prompt = (
                        f"Analyze this resume and provide structured output:\n"
                        "1. Key strengths (skills/technologies)\n"
                        "2. Suggested roles\n"
                        "3. Recommended skills to improve\n"
                        "Return each point as a bullet list clearly.\n\n"
                        f"Resume:\n{content}"
                    )
                    ai_text = model.generate_content(prompt).text
                    ai_result_list = [line.strip(" -•") for line in ai_text.split("\n") if line.strip()]

                    # ----------------- Extract Skills & Roles -----------------
                    skills, roles = [], []
                    for line in ai_result_list:
                        if "skill" in line.lower() or "strength" in line.lower():
                            skills.extend(re.findall(r'\b[A-Za-z+.#]+\b', line))
                        elif "role" in line.lower() or "developer" in line.lower() or "engineer" in line.lower():
                            roles.extend(re.findall(r'\b[A-Za-z ]+\b', line))

                    skills = list(set([s.strip() for s in skills if len(s.strip()) > 2]))
                    roles = list(set([r.strip() for r in roles if len(r.strip()) > 2]))

                    # Build query for jobs (roles + skills)
                    search_query = ", ".join(roles[:2] + skills[:3])

                    if search_query:
                        jobs_data = fetch_linkedin_jobs(
                            query=search_query,
                            location="India",   # ✅ can make dynamic
                            max_results=10
                        )

                except Exception as e:
                    error_message = f"AI analysis or job fetching failed: {str(e)}"

            # ----------------- Resume Tips -----------------
            if get_tips and content:
                try:
                    model = genai.GenerativeModel("gemini-2.5-flash")
                    prompt = f"Provide actionable resume improvement tips based on this resume:\n{content}"
                    tutorial_tips = model.generate_content(prompt).text
                except Exception as e:
                    error_message = f"AI resume tips generation failed: {str(e)}"

    return render_template(
        "resume.html",
        ai_result_list=ai_result_list,
        jobs=jobs_data,
        tutorial_tips=tutorial_tips,
        error_message=error_message,
        resume_content=content
    )

# ✅ Improvements

# ------------------------
# Auth Routes
# ------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # 1️⃣ Backend validations
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))

        if len(phone) != 10 or not phone.isdigit():
            flash("Phone number must be 10 digits", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(phone=phone).first():
            flash("Phone number already registered", "danger")
            return redirect(url_for("register"))

        # 2️⃣ Everything is valid — create user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            email=email,
            password=hashed_password
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error saving user: {str(e)}", "danger")
            return redirect(url_for("register"))

    # GET request
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Validate input
        if not email or not password:
            flash("Please enter both email and password", "danger")
            return redirect(url_for("login"))

        # Find user
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

# ------------------------
# Run App
# ------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("Tables should now be created:", db.inspect(db.engine).get_table_names())
    # app.run(debug=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
