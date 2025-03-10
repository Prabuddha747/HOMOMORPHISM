## TenSEAL Homomorphic Encryption Example: Logistic Regression

This example demonstrates how to perform homomorphic encryption (HE) operations using the TenSEAL library, specifically focusing on training and evaluating a logistic regression model on encrypted data.

**Key Concepts:**

* **Homomorphic Encryption (HE):** Allows computations on encrypted data without decryption.
* **TenSEAL:** A Python library for HE, built on Microsoft SEAL.
* **BFV and CKKS:** HE schemes for integer (BFV) and real number (CKKS) computations.
* **TenSEALContext:** Manages encryption keys and parameters.
* **Encrypted Vectors:** Represent encrypted data.

**Setup and Installation:**

1.  Install TenSEAL:
    ```bash
    pip install tenseal
    ```
2.  Import TenSEAL and create a context:
    ```python
    import tenseal as ts
    context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=4096, plain_modulus=1032193)
    ```

**Basic Operations:**

* Encryption and Decryption:
    ```python
    plain_vector = [60, 66, 73, 81, 90]
    encrypted_vector = ts.bfv_vector(context, plain_vector)
    decrypted_vector = encrypted_vector.decrypt()
    ```
* Homomorphic operations (addition, subtraction, multiplication):
    ```python
    add_result = encrypted_vector + [1, 2, 3, 4, 5]
    sub_result = encrypted_vector - [1, 2, 3, 4, 5]
    mul_result = encrypted_vector * [1, 2, 3, 4, 5]
    ```

**Logistic Regression Example:**

1.  **Data Preparation:**
    * Load and preprocess the Framingham heart disease dataset.
    * Split the data into training and testing sets.
2.  **Plaintext Training:**
    * Train a logistic regression model using PyTorch.
    * Evaluate the model to get a base line accuracy.
3.  **Encrypted Evaluation:**
    * Encrypt the test data using CKKS.
    * Evaluate the trained model on the encrypted test data.
    * Compare the encrypted accuracy to the plaintext accuracy.
4.  **Encrypted Training:**
    * Encrypt the training data.
    * Implement an `EncryptedLR` class to perform training on encrypted data.
    * Train the model on the encrypted data.
    * Evaluate the encrypted trained model on the plaintext test data.
    * Compare the encrypted trained accuracy to the plaintext accuracy.

**Key Takeaways:**

* TenSEAL simplifies homomorphic encryption operations.
* HE enables training and evaluation of machine learning models on encrypted data.
* Performance considerations are crucial, especially for complex computations.
* Ciphertext to plaintext operations are much faster than ciphertext to ciphertext operations.
* The example shows that training on encrypted data can achieve comparable accuracy to training on plaintext data.

**Running the Code:**

1.  Ensure TenSEAL, PyTorch, pandas, and other dependencies are installed.
2.  Download the Framingham heart disease dataset (`framingham.csv`) and place it in the correct directory.
3.  Run the Python script.

This example provides a foundation for exploring homomorphic encryption with TenSEAL for privacy-preserving machine learning.
