FROM python:3.8

# Copy the current directory contents into the container at /app
COPY /app /app

WORKDIR /app
# Install any needed packages specified in requirements.txt
RUN pip install Flask

# Make port 80 available to the world outside this container
EXPOSE 80

# Run app.py when the container launches
CMD ["python", "app.py"]
