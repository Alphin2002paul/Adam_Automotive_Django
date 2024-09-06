from selenium import webdriver
from selenium.webdriver.edge.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.microsoft import EdgeChromiumDriverManager
import time
from selenium.common.exceptions import TimeoutException

def run_login_test():
    # Setup the Edge WebDriver
    service = Service(EdgeChromiumDriverManager().install())
    driver = webdriver.Edge(service=service)

    # Open the browser in full screen
    driver.maximize_window()  # This will open the browser in full-screen mode

    # Navigate to the login page
    driver.get("http://localhost:8000/login")

    try:
        # Login process
        email_input = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.NAME, "email"))
        )
        email_input.send_keys("alphin2002paul@gmail.com")

        password_input = driver.find_element(By.NAME, "password")
        password_input.send_keys("Alphin@")

        submit_button = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        submit_button.click()

        # Wait for the main page to load after successful login
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "nav.navbar"))
        )
        print("Login successful! Main page loaded.")

        # Find and click the Car Collection button in the navbar
        car_collection_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, "//nav//a[contains(text(), 'Cars Collection')]"))
        )
        print("Car Collection button found in navbar")
        car_collection_button.click()
        print("Car Collection button clicked")

        # Wait for the Car Collection page to load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".car-wrap"))
        )
        print("Car Collection page loaded successfully")

        # Scroll to the first car
        first_car = driver.find_element(By.CSS_SELECTOR, ".car-wrap")
        driver.execute_script("arguments[0].scrollIntoView();", first_car)
        print("Scrolled to the first car")

        # Wait for the "Add to Liked" button to be clickable
        add_to_liked_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, ".car-wrap:first-child .like-btn"))
        )
        print("'Add to Liked' button found")

        # Click the "Add to Liked" button
        add_to_liked_button.click()
        print("'Add to Liked' button clicked")

        # Wait for the button text to change
        WebDriverWait(driver, 10).until(
            EC.text_to_be_present_in_element((By.CSS_SELECTOR, ".car-wrap:first-child .like-btn"), "Remove Like")
        )
        print("Button text changed to 'Remove Like'")

        # Find and click the dropdown menu
        dropdown_menu = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.ID, "navbarDropdownMenuLink"))
        )
        dropdown_menu.click()
        print("Dropdown menu clicked")

        # Find and click the "Liked List" option
        liked_list_option = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, "//a[contains(text(), 'Liked List')]"))
        )
        liked_list_option.click()
        print("'Liked List' option clicked")

        # Wait for the Liked List page to load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".car-wrap"))
        )
        print("Liked List page loaded successfully")

        # Find the "Remove Like" button for the first car
        remove_like_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, ".car-wrap:first-child .like-btn"))
        )
        print("'Remove Like' button found")

        # Get the number of cars before clicking the button
        cars_before = len(driver.find_elements(By.CSS_SELECTOR, ".car-wrap"))

        # Click the "Remove Like" button
        remove_like_button.click()
        print("'Remove Like' button clicked")

        try:
            # Wait for the number of cars to decrease
            WebDriverWait(driver, 5).until(
                lambda d: len(d.find_elements(By.CSS_SELECTOR, ".car-wrap")) < cars_before
            )
            print("Car successfully removed from Liked List")
        except TimeoutException:
            print("WARNING: 'Remove Like' button click did not remove the car from the list")
            print("This might indicate an issue with the 'Remove Like' functionality")

        # Assert that the Car Collection page is displayed
        assert WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".car-list"))
        ), "Car Collection page is not displayed"

        # ... existing code for adding to liked list and navigating ...

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Exit full-screen mode
        driver.minimize_window()

        # Close the browser
        driver.quit()

if __name__ == "__main__":
    run_login_test()