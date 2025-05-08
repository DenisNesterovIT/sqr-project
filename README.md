# 💸 Finance Tracker

A personal finance tracker built with **Streamlit** and powered by **FastAPI**, **SQLAlchemy**, and **Pandas**. Track your income, expenses, and visualize your financial health in real-time.

---

## Features

- Interactive dashboards (built with Streamlit + Altair)
- Secure authentication using JWT
- Data persistence with SQLAlchemy and SQLite
- Modular FastAPI backend for APIs
- Built-in Prometheus monitoring support
- Fully tested with Pytest + Coverage
- Static code checks using Flake8 and Bandit

---

## Tech Stack

| Layer      | Tech                                |
|------------|-------------------------------------|
| Frontend   | Streamlit + Altair                  |
| Backend    | FastAPI + Pydantic                  |
| Database   | SQLAlchemy (SQLite)    |
| Auth       | Python-JOSE + Passlib (bcrypt)      |
| Monitoring | Prometheus             |
| Dev Tools  | Poetry, Pytest, Flake8, Bandit|

---

##  Quick Start

### 1. Clone the Repo
```bash
git clone https://github.com/DenisNesterovIT/sqr-project.git
cd sqr-project
```

### 2. Install Dependencies (via Poetry)

```bash
poetry install
```

### 3. Run the Streamlit App (Frontend)

```bash
poetry run streamlit run app.py
```

### 4. Run the FastAPI Backend

```bash
poetry run uvicorn main:app --reload
```

---

## Run All Tests + Coverage

```bash
poetry run pytest --cov=.
```

### Run Linters & Type Checkers

Lint code:

```bash
poetry run flake8 app.py
poetry run flake8 main.py
```

Security check:

```bash
poetry run bandit -r main.py
```


Docstring coverage:

```bash
poetry run interrogate .
```

---

## CI (GitHub Actions)

This project has full **CI** via `GitHub Actions`:

* Runs on `push` and `pull_request`
* Checks: flake8, bandit, pytest + coverage
* Fails the pipeline if any check fails


---

##  Monitoring

* FastAPI backend exposes **Prometheus** metrics at `/metrics`
---


## 📄 License

MIT License.
Feel free to use, modify, and distribute ⭐

---

## 👤 Author

**Denis Nesterov**
📧 [de.nesterov@innopolis.university](mailto:de.nesterov@innopolis.university)

---


