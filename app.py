from flask import Flask, render_template, request, send_file
import pandas as pd
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "output"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    if "file" not in request.files:
        return "No file selected"

    file = request.files["file"]

    if file.filename == "":
        return "Please select a file"

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    # Read file
    if file.filename.lower().endswith(".csv"):
        df = pd.read_csv(file_path)

    elif file.filename.lower().endswith((".xlsx", ".xls")):
        df = pd.read_excel(file_path)

    else:
        return "Only CSV and Excel files are allowed."

    # Detect sensitive columns
    sensitive_columns = []
    column_details = []

    for column in df.columns:

        column_name = str(column).lower()

        category = "Normal"
        risk = "Low"

        if "email" in column_name or "mail" in column_name:
            category = "Email"
            risk = "High"
            sensitive_columns.append(column)

        elif "phone" in column_name or "mobile" in column_name:
            category = "Phone Number"
            risk = "High"
            sensitive_columns.append(column)

        elif "name" in column_name:
            category = "Personal Name"
            risk = "Medium"
            sensitive_columns.append(column)

        elif "aadhaar" in column_name or "pan" in column_name:
            category = "Identity Information"
            risk = "High"
            sensitive_columns.append(column)

        elif "address" in column_name:
            category = "Address"
            risk = "Medium"
            sensitive_columns.append(column)

        elif "age" in column_name:
            category = "Age"
            risk = "Medium"
            sensitive_columns.append(column)

        column_details.append({
            "name": column,
            "category": category,
            "risk": risk
        })

    # Risk score
    total_columns = len(df.columns)
    sensitive_count = len(sensitive_columns)

    if total_columns > 0:
        risk_score = int((sensitive_count / total_columns) * 100)
    else:
        risk_score = 0

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Create anonymized dataset
    safe_df = df.copy()

    for column in sensitive_columns:

        column_name = str(column).lower()

        if "email" in column_name or "mail" in column_name:

            safe_df[column] = safe_df[column].astype(str).apply(
                lambda x: x[0] + "***@" + x.split("@")[1]
                if "@" in x else "***"
            )

        elif "phone" in column_name or "mobile" in column_name:

            safe_df[column] = safe_df[column].astype(str).apply(
                lambda x: x[:2] + "******" + x[-2:]
                if len(x) >= 4 else "****"
            )

        elif "name" in column_name:

            safe_df[column] = safe_df[column].astype(str).apply(
                lambda x: x[0] + "****" if len(x) > 1 else "*"
            )

        elif "aadhaar" in column_name or "pan" in column_name:

            safe_df[column] = safe_df[column].astype(str).apply(
                lambda x: "****" + x[-4:]
                if len(x) >= 4 else "****"
            )

        elif "address" in column_name:

            safe_df[column] = safe_df[column].astype(str).apply(
                lambda x: x[:3] + "****"
                if len(x) > 3 else "****"
            )

    # Save safe dataset
    output_file = os.path.join(
        OUTPUT_FOLDER,
        "DataGuard_Safe_Dataset.csv"
    )

    safe_df.to_csv(output_file, index=False)

    return render_template(
        "result.html",
        filename=file.filename,
        rows=len(df),
        columns=total_columns,
        sensitive_count=sensitive_count,
        risk_score=risk_score,
        risk_level=risk_level,
        column_details=column_details
    )


@app.route("/download")
def download():

    output_file = os.path.join(
        OUTPUT_FOLDER,
        "DataGuard_Safe_Dataset.csv"
    )

    return send_file(
        output_file,
        as_attachment=True,
        download_name="DataGuard_Safe_Dataset.csv"
    )


if __name__ == "__main__":
    app.run(debug=True)