# tests/e2e/test_e2e.py

import pytest  


@pytest.mark.e2e
def test_hello_world(page, fastapi_server):
    """
    Test that the homepage displays "Hello World".

    This test verifies that when a user navigates to the homepage of the application,
    the main header (`<h1>`) correctly displays the text "Hello World". This ensures
    that the server is running and serving the correct template.
    """
    page.goto('http://localhost:8000')
    

    assert page.inner_text('h1') == 'Hello World'

@pytest.mark.e2e
def test_calculator_add(page, fastapi_server):
    """
    Test the addition functionality of the calculator.

    This test simulates a user performing an addition operation using the calculator
    on the frontend. It fills in two numbers, clicks the "Add" button, and verifies
    that the result displayed is correct.
    """
    page.goto('http://localhost:8000')
    
    page.fill('#a', '10')
    
    page.fill('#b', '5')
    
    page.click('button:text("Add")')
    
    assert page.inner_text('#result') == 'Result: 15'

@pytest.mark.e2e
def test_calculator_divide_by_zero(page, fastapi_server):
    """
    Test the divide by zero functionality of the calculator.

    This test simulates a user attempting to divide a number by zero using the calculator.
    It fills in the numbers, clicks the "Divide" button, and verifies that the appropriate
    error message is displayed. This ensures that the application correctly handles invalid
    operations and provides meaningful feedback to the user.
    """
    page.goto('http://localhost:8000')
    
    page.fill('#a', '10')
    
    page.fill('#b', '0')
    
    page.click('button:text("Divide")')

    assert page.inner_text('#result') == 'Error: Cannot divide by zero!'
