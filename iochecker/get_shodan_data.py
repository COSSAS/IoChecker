"""Utilities to communicate with Shodan."""

import logging
from datetime import date
from os import environ

from shodan import Shodan


def get_ip_information(ip: str) -> dict:
    """Retrieve all information stored in Shodan for a given IP.

    Args:
        ip (str): IP address as a string

    Returns:
        dict: dictionary with Shodan output
    """
    host_api = create_shodan_context()

    # Retrieve the host data
    try:
        host_data = host_api.host(ip, history=True)
    except Exception as error:
        logging.error(error)
        return {}

    # Extract the useful features and return result
    return host_data


def extract_relevant_data(host_data: dict, observation_date: date) -> dict[str, object]:
    """Extract relevant data from a Shodan response.

    Args:
        host_data (dict): host data dictionary
        observation_date (date): date to check

    Returns:
        dict[str, object]: relevant data dictionary
    """
    # Initialize objects
    services = {}

    # First, retrieve the general information
    output = {"date": observation_date, "dns": set(), "open_ports": set(), "os": ""}

    # Than, loop through all the services to gather more information
    for period in host_data["data"]:
        # Retrieve the date of this period
        # Every period is a timestamp - service combination,
        # so timestamp occur multiple times in this list,
        # depending on the number of active services
        if date.fromisoformat(period["timestamp"].split("T")[0]) == observation_date:
            # Extract SSH information
            if period.get("ssh"):
                key = (period["port"], "SSH")

                services[key] = {
                    "fingerprint": period["ssh"]["fingerprint"],
                    "hassh": period["ssh"]["hassh"],
                }

            # Extract HTTP information
            if period.get("http"):
                key = (period["port"], "HTTP")

                services[key] = {
                    "html_tags": count_html_tags(period["http"].get("html", "")),
                    "html_title": period["http"].get("title", ""),
                }

            # Extract open ports, DNS and OS information
            output["open_ports"].add(period["port"])  # type: ignore
            output["dns"].update(period["domains"])  # type: ignore
            output["os"] = period.get("os")

    # Add the services dictionary to the output
    output["services"] = services

    return output


def create_shodan_context() -> Shodan:
    """Create a Shodan API object to work with.

    Returns:
        Shodan: Shodan object
    """
    if not environ.get("SHODAN_API_KEY"):
        logging.error("No Shodan API KEY configured in env file.")

    return Shodan(environ.get("SHODAN_API_KEY"))


def count_html_tags(html_input: str) -> int:
    """Count the number of HTML tags present in a HTML document.

    Args:
        html_input (str): HTML output as a string

    Returns:
        int: number of HTML tags
    """
    return round((html_input.count("<") - 1) / 2)
