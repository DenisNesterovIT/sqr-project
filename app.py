import streamlit as st
import requests
import pandas as pd
import altair as alt

API_URL = "http://127.0.0.1:8000"

st.set_page_config(page_title="💰 Finance Tracker", layout="wide")

if "token" not in st.session_state:
    st.session_state.token = None


def get_dashboard(start_date=None, end_date=None):
    """
    Fetch dashboard summary data from the API.

    Args:
        start_date (str, optional): ISO date string to filter records from.
        end_date (str, optional): ISO date string to filter records up to.

    Returns:
        dict: Dashboard data including total income, expenses,
        balance, and records list.
    """
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    params = {}
    if start_date:
        params["start_date"] = start_date
    if end_date:
        params["end_date"] = end_date
    r = requests.get(f"{API_URL}/dashboard", headers=headers, params=params)
    if r.ok:
        return r.json()
    st.error(r.json().get("detail", "Failed to fetch dashboard"))
    return {"total_income": 0, "total_expense": 0, "balance": 0, "records": []}


def login_form():
    """
    Render and handle the user login form.

    Authenticates user by sending credentials to the API.
    Updates session state with access token upon success.
    """
    st.header("🔐 Login")
    u = st.text_input("Username", key="login_username")
    p = st.text_input("Password", type="password", key="login_password")
    if st.button("Login", key="login_btn"):
        if not u or not p:
            st.error("Please fill both fields.")
            return
        r = requests.post(
            f"{API_URL}/login",
            json={
                "username": u,
                "password": p
            }
        )
        if r.ok:
            token = r.json()["access_token"]
            st.session_state.token = token
            st.success("Logged in! Redirecting…")
        else:
            st.error(r.json().get("detail", "Login failed"))


def register_form():
    """
    Render and handle the user registration form.

    Validates user input and creates an account via the API.
    Displays success or error messages based on the response.
    """
    st.header("📝 Register")
    u = st.text_input("Username", key="reg_username")
    e = st.text_input("Email", key="reg_email")
    p = st.text_input("Password", type="password", key="reg_password")
    c = st.text_input("Confirm", type="password", key="reg_confirm")
    if st.button("Register", key="reg_btn"):
        if not u or not e or not p:
            st.error("All fields are required.")
            return
        if p != c:
            st.error("Passwords do not match.")
            return
        r = requests.post(
            f"{API_URL}/register",
            json={
                "username": u,
                "email": e,
                "password": p
            }
        )
        if r.ok:
            st.success("Registered! Please switch to Login.")
        else:
            st.error(r.json().get("detail", "Registration failed"))


def add_record_form():
    """
    Render the form to add a new financial record (income or expense).

    Sends record data to the API and displays confirmation on success.
    """
    with st.expander("➕ Add Record"):
        amt = st.number_input("Amount", key="add_amount", value=0.0)
        typ = st.selectbox("Type", ["income", "expense"], key="add_type")
        cat = st.text_input("Category", key="add_cat")
        desc = st.text_input("Description", key="add_desc")
        if st.button("Add", key="add_btn"):
            r = requests.post(
                f"{API_URL}/records",
                headers={"Authorization": f"Bearer {st.session_state.token}"},
                json={
                    "amount": amt,
                    "type": typ,
                    "category": cat,
                    "description": desc
                }
            )
            if r.ok:
                st.success("Record added")
            else:
                st.error(r.json().get("detail", "Failed to add"))


def show_dashboard():
    """
    Render the main finance dashboard for authenticated users.

    Displays metrics, records list, charts,
    and allows editing and deleting records.
    Provides filter options for date range and adding new records.
    """
    st.title("💰 Your Finance Dashboard")

    add_record_form()

    c1, c2, c3 = st.columns(3)
    with c1:
        sd = st.date_input("From", key="f_date", value=None)
    with c2:
        ed = st.date_input("To", key="t_date", value=None)
    with c3:
        if st.button("Refresh", key="refresh_btn"):
            st.session_state.dashboard = get_dashboard(
                start_date=sd.isoformat() if sd else None,
                end_date=ed.isoformat() if ed else None
            )

    if "dashboard" not in st.session_state:
        st.session_state.dashboard = get_dashboard()

    d = st.session_state.dashboard
    st.metric("Total Income",  f"💚 {d['total_income']}")
    st.metric("Total Expense", f"❤️ {d['total_expense']}")
    st.metric("Balance",       f"💰 {d['balance']}")

    df = pd.DataFrame(d["records"])
    if not df.empty:
        df["date"] = pd.to_datetime(df["date"])
        pie = alt.Chart(df).mark_arc().encode(
            theta="amount:Q",
            color="type:N",
            tooltip=["type", "amount"]
        ).properties(title="Income vs Expense")
        st.altair_chart(pie, use_container_width=True)

    st.subheader("Records")
    for r in d["records"]:
        with st.expander(
            f"{r['type']} • {r['category']} • {r['amount']} ({r['date'][:10]})"
        ):
            st.write(r.get("description", "—"))
            a = st.number_input(
                "Amount",
                value=r["amount"],
                key=f"a_{r['id']}"
            )
            t = st.selectbox(
                "Type",
                ["income", "expense"],
                index=0
                if r["type"] == "income" else 1,
                key=f"t_{r['id']}"
            )
            c = st.text_input(
                "Category",
                value=r["category"],
                key=f"c_{r['id']}"
            )
            dsc = st.text_input(
                "Description",
                value=r.get("description", ""),
                key=f"d_{r['id']}"
            )
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Save", key=f"save_{r['id']}"):
                    requests.put(
                        f"{API_URL}/records/{r['id']}",
                        headers={
                            "Authorization": f"Bearer {st.session_state.token}"
                        },
                        json={
                            "amount": a,
                            "type": t,
                            "category": c,
                            "description": dsc
                        }
                    )
                    st.success("Updated")
            with col2:
                if st.button("Delete", key=f"del_{r['id']}"):
                    requests.delete(
                        f"{API_URL}/records/{r['id']}",
                        headers={
                            "Authorization": f"Bearer {st.session_state.token}"
                        }
                    )
                    st.success("Deleted")

    if st.button("🚪 Logout", key="logout_btn"):
        st.session_state.token = None


if not st.session_state.token:
    choice = st.radio("Action", ["Login", "Register"], key="auth")
    if choice == "Login":
        login_form()
    else:
        register_form()
else:
    show_dashboard()
