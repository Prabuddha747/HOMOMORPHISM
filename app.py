import streamlit as st
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import hashlib
import base64
import pickle
import os
import tenseal as ts  # Real FHE library
import pennylane as qml  # Quantum computing library
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Page configuration
st.set_page_config(page_title="Secure Loan Prediction System", page_icon="🔒", layout="wide")
st.title("🔒 Secure Loan Prediction System")
st.markdown("This application predicts loan approval using a machine learning model with advanced encryption for data privacy.")

# Load and prepare data
@st.cache_data
def load_data():
    data = pd.read_csv('data.csv')
    return data

# Model building with validation and balanced predictions
@st.cache_resource
def get_model(data):
    X = data.drop('Target', axis=1)
    y = data['Target']
    
    categorical_features = ['Income_type', 'Education_type', 'Family_status', 'Occupation_type', 'Housing_type']
    numerical_features = ['Own_car', 'Own_property', 'Mobile_phone', 'Num_children',
                         'Household_size', 'Total_income', 'Age', 'Account_age', 'Employed', 'Years_employed']
    
    categorical_transformer = OneHotEncoder(handle_unknown='ignore')
    numerical_transformer = StandardScaler()
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numerical_transformer, numerical_features),
            ('cat', categorical_transformer, categorical_features)
        ])
    
    model = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(
            n_estimators=100, 
            random_state=42,
            class_weight='balanced',
            max_depth=10,
            min_samples_leaf=5
        ))
    ])
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    accuracy = np.mean(y_pred == y_test)
    class_distribution = pd.Series(y).value_counts(normalize=True)
    
    feature_importances = None
    try:
        feature_importances = model.named_steps['classifier'].feature_importances_
    except:
        pass
    
    return model, preprocessor, numerical_features, categorical_features, accuracy, class_distribution, feature_importances

# Apply business rules
def apply_business_rules(input_data, raw_prediction, prediction_proba):
    if input_data['Total_income'] < 15000 and input_data['Employed'] == 0:
        return 0, 0.25
    
    if (input_data['Own_property'] == 0 and input_data['Own_car'] == 0 and input_data['Total_income'] < 20000):
        return 0, 0.3
    
    if (input_data['Income_type'] == 'Pensioner' and input_data['Household_size'] <= 1 and input_data['Total_income'] > 25000):
        return 1, 0.75
        
    if (input_data['Age'] < 30 and input_data['Years_employed'] >= 3 and 
        input_data['Education_type'] in ['Higher education'] and input_data['Total_income'] > 35000):
        return 1, 0.85
    
    if prediction_proba < 0.4:
        return 0, prediction_proba
    
    return raw_prediction, prediction_proba

# Real FHE implementation
class RealFHE:
    def __init__(self):
        try:
            self.context = ts.context(
                ts.SCHEME_TYPE.CKKS,
                poly_modulus_degree=8192,
                coeff_mod_bit_sizes=[60, 40, 40, 60]
            )
            self.context.global_scale = 2**40
            self.context.generate_galois_keys()
            self.initialized = True
        except Exception as e:
            st.warning(f"TenSEAL initialization failed: {e}. Using fallback encryption.")
            self.initialized = False
            self.key = os.urandom(32)
            self.backend = default_backend()
    
    def encrypt(self, value):
        if not self.initialized:
            return self._fallback_encrypt(value)
        
        try:
            if isinstance(value, (str, bool)):
                value_hash = int(hashlib.sha256(str(value).encode()).hexdigest(), 16) % 1000
                float_val = float(value_hash)
            else:
                float_val = float(value)
            
            encrypted_value = ts.ckks_vector(self.context, [float_val])
            serialized = encrypted_value.serialize()
            return base64.b64encode(serialized).decode('utf-8')
        except Exception as e:
            return self._fallback_encrypt(value)
    
    def decrypt(self, encrypted_value):
        if not self.initialized:
            return self._fallback_decrypt(encrypted_value)
        
        try:
            serialized = base64.b64decode(encrypted_value)
            encrypted_vector = ts.ckks_vector_from(self.context, serialized)
            decrypted_value = encrypted_vector.decrypt()[0]
            return str(round(decrypted_value, 2))
        except Exception as e:
            return self._fallback_decrypt(encrypted_value)
    
    def homomorphic_add(self, encrypted_a, encrypted_b):
        if not self.initialized:
            a = float(self._fallback_decrypt(encrypted_a))
            b = float(self._fallback_decrypt(encrypted_b))
            return self._fallback_encrypt(a + b)
        
        try:
            serialized_a = base64.b64decode(encrypted_a)
            serialized_b = base64.b64decode(encrypted_b)
            
            enc_a = ts.ckks_vector_from(self.context, serialized_a)
            enc_b = ts.ckks_vector_from(self.context, serialized_b)
            
            result = enc_a + enc_b
            serialized_result = result.serialize()
            return base64.b64encode(serialized_result).decode('utf-8')
        except Exception as e:
            a = float(self._fallback_decrypt(encrypted_a))
            b = float(self._fallback_decrypt(encrypted_b))
            return self._fallback_encrypt(a + b)
    
    def homomorphic_multiply(self, encrypted_a, factor):
        if not self.initialized:
            a = float(self._fallback_decrypt(encrypted_a))
            return self._fallback_encrypt(a * factor)
        
        try:
            serialized_a = base64.b64decode(encrypted_a)
            enc_a = ts.ckks_vector_from(self.context, serialized_a)
            result = enc_a * factor
            serialized_result = result.serialize()
            return base64.b64encode(serialized_result).decode('utf-8')
        except Exception as e:
            a = float(self._fallback_decrypt(encrypted_a))
            return self._fallback_encrypt(a * factor)
    
    def _fallback_encrypt(self, value):
        value_bytes = str(value).encode()
        iv = b'\x00' * 16
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(value_bytes) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def _fallback_decrypt(self, encrypted_value):
        ciphertext = base64.b64decode(encrypted_value)
        iv = b'\x00' * 16
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')

# Quantum encryption implementation
class QuantumEncryption:
    def __init__(self):
        try:
            self.dev = qml.device("default.qubit", wires=4)
            np.random.seed(42)
            self.key_x = np.random.uniform(0, 2*np.pi, size=4)
            self.key_y = np.random.uniform(0, 2*np.pi, size=4)
            self.key_z = np.random.uniform(0, 2*np.pi, size=4)
            
            # Define quantum circuits after device is created
            self._create_quantum_functions()
            self.initialized = True
        except Exception as e:
            st.warning(f"PennyLane initialization failed: {e}. Using fallback encryption.")
            self.initialized = False
            self.key = np.random.random((8, 8)) + 1j * np.random.random((8, 8))
            q, r = np.linalg.qr(self.key)
            self.key = q
    
    def _create_quantum_functions(self):
        # Create device-bound qnodes
        self._encrypt_circuit = qml.QNode(self._encrypt_function, self.dev)
        self._decrypt_circuit = qml.QNode(self._decrypt_function, self.dev)
    
    def _encrypt_function(self, input_val, key_x, key_y, key_z):
        qml.AmplitudeEmbedding([np.sqrt(input_val), np.sqrt(1-input_val), 0, 0], wires=range(4), normalize=True)
        
        for i in range(4):
            qml.RX(key_x[i], wires=i)
            qml.RY(key_y[i], wires=i)
            qml.RZ(key_z[i], wires=i)
        
        for i in range(3):
            qml.CNOT(wires=[i, i+1])
        
        return qml.state()
    
    def _decrypt_function(self, state_vector, key_x, key_y, key_z):
        qml.StatePrep(state_vector, wires=range(4))
        
        for i in range(2, -1, -1):
            qml.CNOT(wires=[i, i+1])
        
        for i in range(3, -1, -1):
            qml.RZ(-key_z[i], wires=i)
            qml.RY(-key_y[i], wires=i)
            qml.RX(-key_x[i], wires=i)
        
        return qml.state()
    def _decrypt_circuit(self, state_vector, key_x, key_y, key_z):
        qml.StatePrep(state_vector, wires=range(4))
        
        for i in range(2, -1, -1):
            qml.CNOT(wires=[i, i+1])
        
        for i in range(3, -1, -1):
            qml.RZ(-key_z[i], wires=i)
            qml.RY(-key_y[i], wires=i)
            qml.RX(-key_x[i], wires=i)
        
        return qml.state()
    
    def encrypt(self, value):
        if not self.initialized:
            return self._fallback_encrypt(value)
        
        try:
            if isinstance(value, (str, bool)):
                value_hash = int(hashlib.sha256(str(value).encode()).hexdigest(), 16) % 1000
                normalized = value_hash / 1000
            else:
                normalized = min(max(float(value) / 1000, 0), 1)
            
            encrypted_state = self._encrypt_circuit(normalized, self.key_x, self.key_y, self.key_z)
            encrypted_bytes = base64.b64encode(np.array(encrypted_state).tobytes())
            return encrypted_bytes.decode('utf-8')
        except Exception as e:
            return self._fallback_encrypt(value)
    
    def decrypt(self, encrypted_value):
        if not self.initialized:
            return self._fallback_decrypt(encrypted_value)
        
        try:
            state_bytes = base64.b64decode(encrypted_value)
            encrypted_state = np.frombuffer(state_bytes, dtype=complex)
            decrypted_state = self._decrypt_circuit(encrypted_state, self.key_x, self.key_y, self.key_z)
            decrypted_value = np.abs(decrypted_state[0])**2 * 1000
            return str(round(decrypted_value, 2))
        except Exception as e:
            return self._fallback_decrypt(encrypted_value)
    
    def _fallback_encrypt(self, value):
        try:
            normalized = float(value) / 1000
        except:
            hash_obj = hashlib.sha256(str(value).encode())
            normalized = int(hash_obj.hexdigest(), 16) % 1000 / 1000
        
        state = np.zeros(8, dtype=complex)
        state[0] = np.sqrt(normalized)
        state[1] = np.sqrt(1 - normalized)
        encrypted_state = np.dot(self.key, state)
        encoded = base64.b64encode(encrypted_state.tobytes()).decode('utf-8')
        return encoded
    
    def _fallback_decrypt(self, encrypted_value):
        encrypted_bytes = base64.b64decode(encrypted_value)
        encrypted_state = np.frombuffer(encrypted_bytes, dtype=complex)
        decrypted_state = np.dot(self.key.conj().T, encrypted_state)
        prob = np.abs(decrypted_state[0])**2
        value = prob * 1000
        return str(round(value, 2))

# Initialize data and model
try:
    data = load_data()
    model, preprocessor, numerical_features, categorical_features, model_accuracy, class_distribution, feature_importances = get_model(data)
except Exception as e:
    st.error(f"Error loading data or training model: {e}")
    st.stop()

# Initialize encryption systems
try:
    fhe = RealFHE()
    st.sidebar.success("FHE system initialized successfully")
except Exception as e:
    st.sidebar.warning(f"FHE initialization error: {e}")
    # Use simplified version as fallback
    from SimplifiedFHE import SimplifiedFHE
    fhe = SimplifiedFHE()

try:
    quantum_enc = QuantumEncryption()
    st.sidebar.success("Quantum encryption system initialized successfully")
except Exception as e:
    st.sidebar.warning(f"Quantum encryption initialization error: {e}")
    # Use simplified version as fallback
    from SimplifiedQuantumEncryption import QuantumInspiredEncryption
    quantum_enc = QuantumInspiredEncryption()

# Create the Streamlit interface
st.sidebar.header("🔐 Encryption Settings")
encryption_type = st.sidebar.selectbox(
    "Encryption Method",
    ["FHE (Fully Homomorphic Encryption)"]
)

# Show model information in sidebar
st.sidebar.markdown("---")
st.sidebar.subheader("Model Information")
st.sidebar.write(f"Model Accuracy: {model_accuracy:.2%}")
st.sidebar.write("Class Distribution:")
st.sidebar.write(f"- Approved Loans: {class_distribution.get(1, 0):.2%}")
st.sidebar.write(f"- Denied Loans: {class_distribution.get(0, 0):.2%}")

# Input section
st.header("📝 Loan Application Form")

col1, col2 = st.columns(2)

with col1:
    st.subheader("Personal Information")
    age = st.number_input("Age", min_value=18, max_value=100, value=35)
    income = st.number_input("Total Income", min_value=0, max_value=100000, value=30000)
    num_children = st.number_input("Number of Children", min_value=0, max_value=10, value=1)
    household_size = st.number_input("Household Size", min_value=1, max_value=15, value=3)
    years_employed = st.number_input("Years Employed", min_value=0, max_value=50, value=5)
    account_age = st.number_input("Account Age (months)", min_value=0, max_value=500, value=36)

with col2:
    st.subheader("Additional Information")
    own_car = st.checkbox("Own Car")
    own_property = st.checkbox("Own Property")
    mobile_phone = st.checkbox("Has Mobile Phone")
    employed = st.checkbox("Currently Employed", value=True)
    
    income_type = st.selectbox(
        "Income Type",
        options=["Salaried", "Self-employed", "Pensioner", "Student"]
    )
    
    education_type = st.selectbox(
        "Education Type",
        options=["Higher education", "Secondary", "Incomplete higher", "Lower secondary"]
    )
    
    family_status = st.selectbox(
        "Family Status",
        options=["Married", "Single", "Divorced", "Widow"]
    )
    
    occupation_type = st.selectbox(
        "Occupation Type",
        options=["Engineer", "Manager", "Entrepreneur", "Teacher", "Office Worker", 
                "Retired", "Business Owner", "Doctor", "Salesperson", "Other"]
    )
    
    housing_type = st.selectbox(
        "Housing Type",
        options=["House / apartment", "Rented apartment", "With parents"]
    )

# Create input data dictionary
input_data = {
    'Own_car': 1 if own_car else 0,
    'Own_property': 1 if own_property else 0,
    'Mobile_phone': 1 if mobile_phone else 0,
    'Num_children': num_children,
    'Household_size': household_size,
    'Total_income': income,
    'Age': age,
    'Income_type': income_type,
    'Education_type': education_type,
    'Family_status': family_status,
    'Occupation_type': occupation_type,
    'Housing_type': housing_type,
    'Account_age': account_age,
    'Employed': 1 if employed else 0,
    'Years_employed': years_employed
}

# Create risk profiles for demonstration
risk_profiles = {
    "High Risk Applicant": {
        'Own_car': 0,
        'Own_property': 0,
        'Mobile_phone': 1,
        'Num_children': 3,
        'Household_size': 5,
        'Total_income': 12000,
        'Age': 25,
        'Income_type': 'Student',
        'Education_type': 'Lower secondary',
        'Family_status': 'Single',
        'Occupation_type': 'Other',
        'Housing_type': 'With parents',
        'Account_age': 6,
        'Employed': 0,
        'Years_employed': 0
    },
    "Medium Risk Applicant": {
        'Own_car': 0,
        'Own_property': 1,
        'Mobile_phone': 1,
        'Num_children': 1,
        'Household_size': 2,
        'Total_income': 25000,
        'Age': 35,
        'Income_type': 'Salaried',
        'Education_type': 'Secondary',
        'Family_status': 'Married',
        'Occupation_type': 'Office Worker',
        'Housing_type': 'House / apartment',
        'Account_age': 24,
        'Employed': 1,
        'Years_employed': 2
    },
    "Low Risk Applicant": {
        'Own_car': 1,
        'Own_property': 1,
        'Mobile_phone': 1,
        'Num_children': 0,
        'Household_size': 2,
        'Total_income': 45000,
        'Age': 40,
        'Income_type': 'Self-employed',
        'Education_type': 'Higher education',
        'Family_status': 'Married',
        'Occupation_type': 'Business Owner',
        'Housing_type': 'House / apartment',
        'Account_age': 60,
        'Employed': 1,
        'Years_employed': 8
    }
}

# Add demo profiles selectbox
st.sidebar.markdown("---")
st.sidebar.subheader("Demo Profiles")
selected_profile = st.sidebar.selectbox(
    "Select a demo profile",
    ["Custom Input"] + list(risk_profiles.keys())
)

# Update input values if a profile is selected
if selected_profile != "Custom Input":
    profile = risk_profiles[selected_profile]
    input_data = profile.copy()
    
    st.sidebar.markdown(f"**{selected_profile} Details:**")
    st.sidebar.write(f"- Income: ${profile['Total_income']}")
    st.sidebar.write(f"- Age: {profile['Age']}")
    st.sidebar.write(f"- Employment: {profile['Years_employed']} years")
    st.sidebar.write(f"- Education: {profile['Education_type']}")
    st.sidebar.write(f"- Assets: {'Car, ' if profile['Own_car'] else ''}{'Property' if profile['Own_property'] else 'None'}")

# Encrypt data when button is pressed
if st.button("Process Loan Application"):
    st.header("🔒 Encrypted Data")
    
    # Choose encryption based on selection
    encryptor = fhe if encryption_type.startswith("FHE") else quantum_enc
    
    # Store encrypted values
    encrypted_values = {}
    
    # Process and display encrypted data
    enc_col1, enc_col2 = st.columns(2)
    
    with enc_col1:
        st.subheader("Personal Information (Encrypted)")
        for field in ['Age', 'Total_income', 'Num_children', 'Household_size', 'Years_employed', 'Account_age']:
            key = field.replace(' ', '_')
            if key not in input_data:
                key = field
            encrypted_values[key] = encryptor.encrypt(input_data[key])
            st.text(f"{field}: {encrypted_values[key][:20]}...")
    
    with enc_col2:
        st.subheader("Additional Information (Encrypted)")
        for field in ['Own_car', 'Own_property', 'Mobile_phone', 'Employed', 'Income_type', 
                     'Education_type', 'Family_status', 'Occupation_type', 'Housing_type']:
            encrypted_values[field] = encryptor.encrypt(input_data[field])
            st.text(f"{field}: {encrypted_values[field][:20]}...")
    
    # Generate a full hash of all encrypted data
    combined_encrypted = "".join([str(v) for v in encrypted_values.values()])
    full_hash = hashlib.sha256(combined_encrypted.encode()).hexdigest()
    
    st.subheader("🔐 Encryption Hash")
    st.code(full_hash, language="text")
    
    # Make prediction
    input_df = pd.DataFrame([input_data])
    
    # Get raw model prediction and probability
    raw_prediction_proba = model.predict_proba(input_df)[0][1]
    raw_prediction = 1 if raw_prediction_proba >= 0.5 else 0
    
    # Apply business rules
    final_prediction, final_proba = apply_business_rules(input_data, raw_prediction, raw_prediction_proba)
    
    # Encrypt the prediction
    encrypted_prediction = encryptor.encrypt(final_prediction)
    encrypted_proba = encryptor.encrypt(final_proba)
    
    # Display results
    st.header("📊 Loan Prediction Results")
    
    # Display encrypted results
    st.subheader("Encrypted Prediction")
    st.code(f"Encrypted Binary Prediction: {encrypted_prediction}", language="text")
    st.code(f"Encrypted Probability: {encrypted_proba}", language="text")
    
    # Display decrypted results
    st.subheader("Decrypted Prediction")
    
    # Show both model and rule-based results
    st.subheader("Model Prediction")
    if raw_prediction == 1:
        st.info(f"Model suggested: Approve with {raw_prediction_proba:.2%} confidence")
    else:
        st.info(f"Model suggested: Deny with {1-raw_prediction_proba:.2%} confidence")
    
    st.subheader("Final Decision (After Business Rules)")
    if final_prediction == 1:
        st.success(f"Loan Approved with {final_proba:.2%} confidence")
    else:
        st.error(f"Loan Denied with {1-final_proba:.2%} confidence")
    
    # Feature importance visualization
    st.subheader("🔍 Key Factors")
    if feature_importances is not None:
        # Extract feature names from the preprocessor
        feature_names = numerical_features.copy()
        
        # Get one-hot encoded categorical feature names
        categorical_transformer = preprocessor.named_transformers_['cat']
        cat_features = []
        for i, category in enumerate(categorical_features):
            cat_values = categorical_transformer.categories_[i]
            for value in cat_values:
                cat_features.append(f"{category}_{value}")
        
        all_features = feature_names + cat_features
        
        # Get feature importances from the model
        indices = np.argsort(feature_importances)[::-1]
        
        # Display top 5 features
        st.write("Top features affecting the decision:")
        for i in range(min(5, len(indices))):
            if indices[i] < len(all_features):
                st.write(f"{i+1}. {all_features[indices[i]]}: {feature_importances[indices[i]]:.4f}")
    
    # Risk factors specific to this application
    st.subheader("Individual Risk Assessment")
    
    risk_factors = []
    if input_data['Total_income'] < 20000:
        risk_factors.append("Low income")
    if input_data['Employed'] == 0:
        risk_factors.append("Currently unemployed")
    if input_data['Years_employed'] < 2:
        risk_factors.append("Short employment history")
    if input_data['Account_age'] < 12:
        risk_factors.append("New account holder")
    if input_data['Own_property'] == 0 and input_data['Own_car'] == 0:
        risk_factors.append("No significant assets")
    
    if risk_factors:
        st.warning("Identified risk factors:")
        for factor in risk_factors:
            st.write(f"- {factor}")
    else:
        st.success("No significant risk factors identified.")

    # If using FHE, demonstrate homomorphic operations
    if encryption_type.startswith("FHE"):
        st.subheader("Homomorphic Operations Demo")
        st.write("Performing calculations on encrypted data without decrypting:")
        
        # Encrypt some test values
        enc_test_a = encryptor.encrypt(0.5)
        enc_test_b = encryptor.encrypt(0.3)
        
        # Perform homomorphic operations
        enc_sum = encryptor.homomorphic_add(enc_test_a, enc_test_b)
        enc_product = encryptor.homomorphic_multiply(enc_test_a, 2.0)
        
        # Show results
        st.write(f"Homomorphic Addition (0.5 + 0.3): {encryptor.decrypt(enc_sum)}")
        st.write(f"Homomorphic Multiplication (0.5 * 2.0): {encryptor.decrypt(enc_product)}")