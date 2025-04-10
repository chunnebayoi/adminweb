import streamlit as st
import hashlib
from collections import deque, Counter

# === Dữ liệu giả lập ===
# Cơ sở dữ liệu tài khoản (giả lập)
if 'users_db' not in st.session_state:
    st.session_state.users_db = {
        "admin": {
            "password": "admin123",
            "role": "admin",
            "active_key": None
        },
        "giangson2102": {
            "password": "son2102",
            "role": "admin",
            "active_key": None
        }
    }

if 'used_keys' not in st.session_state:
    st.session_state.used_keys = set(["2102"])

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if 'recent_results' not in st.session_state:
    st.session_state.recent_results = deque(maxlen=10)

if 'role' not in st.session_state:
    st.session_state.role = ""

# === Hàm xử lý chính ===
def complex_calculation(input_str: str) -> float:
    md5_hash = int(hashlib.md5(input_str.encode()).hexdigest(), 16)
    sha256_hash = int(hashlib.sha256(input_str.encode()).hexdigest(), 16)
    blake2b_hash = int(hashlib.blake2b(input_str.encode()).hexdigest(), 16)
    combined_hash = (
        (md5_hash % 100) * 0.3 +
        (sha256_hash % 100) * 0.4 +
        (blake2b_hash % 100) * 0.3
    )
    return combined_hash % 100

def bayesian_adjustment(recent_results: deque) -> float:
    count = Counter(recent_results)
    total = len(recent_results)
    if total == 0:
        return 50.0
    prob_xiu = (count["Xỉu"] + 1) / (total + 2)
    return prob_xiu * 100

def detect_trend(recent_results: deque) -> str:
    if len(recent_results) < 4:
        return "Không đủ dữ liệu phân tích cầu."
    trend_str = ''.join(['T' if res == "Tài" else 'X' for res in recent_results])
    if trend_str.endswith('TTTT'):
        return "Cầu bệt Tài"
    elif trend_str.endswith('XXXX'):
        return "Cầu bệt Xỉu"
    elif trend_str.endswith('TXTX'):
        return "Cầu 1-1"
    elif trend_str.endswith('TXT'):
        return "Cầu 1-2-1"
    elif trend_str.endswith('TTTX'):
        return "Cầu bệt ngắt (Tài ngắt)"
    elif trend_str.endswith('XXXT'):
        return "Cầu bệt ngắt (Xỉu ngắt)"
    elif trend_str.endswith('TXXT'):
        return "Cầu 2-1-2"
    elif trend_str.endswith('XXTXX'):
        return "Cầu 3-2"
    if "TTT" in trend_str[-5:] and trend_str[-1] == "X":
        return "Cầu bẻ từ Tài sang Xỉu"
    elif "XXX" in trend_str[-5:] and trend_str[-1] == "T":
        return "Cầu bẻ từ Xỉu sang Tài"
    return "Cầu không xác định"

def adjust_prediction(percentage: float, trend: str) -> float:
    if trend == "Cầu bệt Tài":
        percentage -= 7
    elif trend == "Cầu bệt Xỉu":
        percentage += 7
    elif trend == "Cầu 1-1":
        percentage += 5 if percentage > 50 else -5
    elif trend == "Cầu 1-2-1":
        percentage += 3
    elif trend in ["Cầu bệt ngắt (Tài ngắt)", "Cầu bệt ngắt (Xỉu ngắt)"]:
        percentage += 2
    elif trend == "Cầu 2-1-2":
        percentage -= 4
    elif trend == "Cầu 3-2":
        percentage += 6
    elif trend == "Cầu bẻ từ Tài sang Xỉu":
        percentage += 10
    elif trend == "Cầu bẻ từ Xỉu sang Tài":
        percentage -= 10
    return max(0, min(100, percentage))

# === Giao diện chính ===
st.set_page_config(page_title="Tool Dự Đoán Tài Xỉu", layout="centered")
st.title("🎲 Dự Đoán Tài Xỉu & Phân Tích Cầu SUNWIN")

menu = st.sidebar.selectbox("🔐 Chọn chức năng:", ["Đăng nhập", "Đăng ký", "👑 Quản lý Key (Admin)"])

if menu == "Đăng ký":
    st.subheader("📝 Đăng ký tài khoản")
    new_username = st.text_input("Tên tài khoản mới")
    new_password = st.text_input("Mật khẩu", type="password")
    if st.button("Tạo tài khoản"):
        if new_username in st.session_state.users_db:
            st.error("❌ Tài khoản đã tồn tại.")
        else:
            st.session_state.users_db[new_username] = {
                "password": new_password,
                "role": "user",
                "active_key": ""
            }
            st.success("✅ Tạo tài khoản thành công. Chờ cấp key để sử dụng.")

elif menu == "Đăng nhập":
    st.subheader("🔐 Đăng nhập")
    username = st.text_input("Tên tài khoản")
    password = st.text_input("Mật khẩu", type="password")
    user_key = st.text_input("🔑 Nhập key kích hoạt")
    if st.button("Đăng nhập"):
        user_data = st.session_state.users_db.get(username)
        if user_data and user_data["password"] == password:
            if user_data["role"] == "admin":
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.role = "admin"
                st.success("✅ Đăng nhập admin thành công")
            elif user_key == user_data.get("active_key") and user_key not in st.session_state.used_keys:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.role = "user"
                st.session_state.used_keys.add(user_key)
                st.session_state.users_db[username]["active_key"] = ""  # Vô hiệu hóa key sau khi dùng
                st.success(f"🎉 Đăng nhập thành công. Chào {username}!")
            else:
                st.error("❌ Sai key hoặc key đã được sử dụng.")
        else:
            st.error("❌ Sai tài khoản hoặc mật khẩu.")

elif menu == "👑 Quản lý Key (Admin)":
    st.subheader("🔑 Cấp Key Kích Hoạt Cho Tài Khoản")
    if st.session_state.get("role") == "admin":
        admin_user = st.text_input("👤 Nhập tên tài khoản cần cấp key")
        admin_key = st.text_input("🔐 Nhập key muốn cấp")
        if st.button("Cấp key"):
            if admin_user in st.session_state.users_db:
                if admin_key in st.session_state.used_keys:
                    st.error("❌ Key này đã được sử dụng, chọn key khác.")
                else:
                    st.session_state.users_db[admin_user]["active_key"] = admin_key
                    st.success(f"✅ Đã cấp key cho tài khoản: {admin_user}")
            else:
                st.error("❌ Không tìm thấy tài khoản này.")
    else:
        st.warning("🔒 Chỉ tài khoản admin mới truy cập được mục này.")

# === Giao diện chính sau đăng nhập ===
if st.session_state.logged_in and st.session_state.role == "user":
    input_str = st.text_input("🎰 Nhập mã phiên hoặc chuỗi bất kỳ:")
    analysis_mode = st.radio("🧠 Chế độ phân tích:", ["Cơ bản", "Nâng cao (AI + Phân tích cầu)"])

    if input_str:
        base_percent = complex_calculation(input_str)
        trend = detect_trend(st.session_state.recent_results)
        bayes_percent = bayesian_adjustment(st.session_state.recent_results)
        final_percent = base_percent if analysis_mode == "Cơ bản" else adjust_prediction(bayes_percent, trend)

        st.subheader("📊 Kết quả dự đoán")
        st.markdown(f"**🟢 Tài:** `{100 - final_percent:.2f}%`")
        st.markdown(f"**🔵 Xỉu:** `{final_percent:.2f}%`")
        st.markdown(f"**📈 Phân tích cầu:** `{trend}`)

        result = st.selectbox("📝 Nhập kết quả thực tế:", ["", "Tài", "Xỉu"])
        if result:
            st.session_state.recent_results.append(result)
            st.success(f"✅ Đã lưu kết quả: {result}")

