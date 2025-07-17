# Use the official Python 3.12 slim image as the base image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements.txt file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire application code to the working directory
COPY . .

# Set environment variable to ensure Flask runs in production mode
ENV FLASK_ENV=production

# Expose the port the app runs on
EXPOSE 8989

# Command to run the Flask application
CMD ["python", "app.py"]