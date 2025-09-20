import requests
from bs4 import BeautifulSoup

def fetch_linkedin_jobs(query, location, max_results=10):
    jobs_list = []

    # Ensure max_results is an integer
    try:
        max_results = int(max_results)
    except:
        max_results = 10

    # Format URL
    search_query = query.replace(" ", "%20")
    search_location = location.replace(" ", "%20")
    url = f"https://www.linkedin.com/jobs/search/?keywords={search_query}&location={search_location},india"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return [{"title": "Failed to fetch jobs", "company": "", "location": "", "link": ""}]

    soup = BeautifulSoup(response.text, "html.parser")
    jobs = soup.find_all("div", class_="base-card")[:max_results]

    for job in jobs:
        title = job.find("h3").text.strip() if job.find("h3") else "N/A"
        company = job.find("h4").text.strip() if job.find("h4") else "N/A"
        loc = job.find("span", class_="job-search-card__location").text.strip() if job.find("span", class_="job-search-card__location") else "N/A"
        link = job.find("a")["href"] if job.find("a") else "#"

        jobs_list.append({
            "title": title,
            "company": company,
            "location": loc,
            "link": link
        })

    return jobs_list

# from selenium import webdriver
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.common.by import By
# from selenium.webdriver.chrome.service import Service
# from webdriver_manager.chrome import ChromeDriverManager
# from datetime import datetime
# import time

# def fetch_linkedin_jobs(query, location, max_results=10):
#     jobs_list = []

#     # Ensure max_results is an integer
#     try:
#         max_results = int(max_results)
#     except (ValueError, TypeError):
#         max_results = 10

#     # Selenium headless browser setup
#     options = Options()
#     options.add_argument("--headless")  # Run in headless mode
#     options.add_argument("--disable-gpu")
#     options.add_argument("--no-sandbox")
#     options.add_argument("--window-size=1920,1080")

#     # Setup ChromeDriver using webdriver-manager
#     driver = webdriver.Chrome(
#         service=Service(ChromeDriverManager().install()),
#         options=options
#     )

#     try:
#         # Format URL
#         search_query = query.replace(" ", "%20")
#         search_location = location.replace(" ", "%20")
#         url = f"https://www.linkedin.com/jobs/search/?keywords={search_query}&location={search_location},india"

#         driver.get(url)
#         time.sleep(5)  # wait for page to load JS content

#         # Find job cards and limit to max_results
#         job_cards = driver.find_elements(By.CLASS_NAME, "base-card")[:max_results]

#         for card in job_cards:
#             try:
#                 title = card.find_element(By.TAG_NAME, "h3").text.strip()
#             except:
#                 title = "N/A"

#             try:
#                 company = card.find_element(By.TAG_NAME, "h4").text.strip()
#             except:
#                 company = "N/A"

#             try:
#                 loc = card.find_element(By.CLASS_NAME, "job-search-card__location").text.strip()
#             except:
#                 loc = "N/A"

#             try:
#                 link = card.find_element(By.TAG_NAME, "a").get_attribute("href")
#             except:
#                 link = "#"

#             # Get posted date if available
#             try:
#                 posted_elem = card.find_element(By.TAG_NAME, "time")
#                 posted_date = datetime.fromisoformat(posted_elem.get_attribute("datetime").replace("Z", "+00:00"))
#                 days_ago = (datetime.utcnow() - posted_date).days
#                 posted = f"{days_ago} days ago" if days_ago > 0 else "Today"
#             except:
#                 posted = "N/A"

#             jobs_list.append({
#                 "title": title,
#                 "company": company,
#                 "location": loc,
#                 "link": link,
#                 "posted": posted
#             })

#     finally:
#         driver.quit()

#     return jobs_list
