"""Utilities to communicate with Censys."""

import logging
from datetime import date
from os import environ

from censys.common.exceptions import CensysUnauthorizedException
from censys.search import CensysHosts


def get_ip_information(ip: str, at_date: date) -> dict:
    """Retrieve all information stored in Censys for a given IP.

    Args:
        ip (str): IP to search for
        at_date (date): date to search for

    Returns:
        dict: dictionary with Censys output
    """
    host_search = create_censys_context()

    # Retrieve the host data
    try:
        host_data = host_search.view(ip, at_time=at_date)
    except CensysUnauthorizedException as error:
        logging.error(error)
        return {}

    return host_data


def extract_relevant_data(host_data: dict, observation_date: date) -> dict[str, object]:
    """Extract relevant data from a Censys host result.

    Args:
        host_data (dict): dictionary with host data
        observation_date (date): observation date

    Returns:
        dict[str, object]: relevant data dictionary
    """
    # Initialize objects
    services = {}

    # First, retrieve the general information
    output = {
        "os": host_data.get("operating_system", {}).get(
            "uniform_resource_identifier", ""
        ),
        "date": observation_date,
        "open_ports": set(),
        "dns": set(),
    }

    # Then, loop through all the services to gather more information
    for service in host_data.get("services", []):
        output["open_ports"].add(service["port"])

        key = (service["port"], service["service_name"])

        # Extract different features per protocol
        match service["service_name"]:
            case "SSH":
                # print(service)
                services[key] = {
                    "fingerprint": service.get("ssh", {})
                    .get("server_host_key", {})
                    .get("fingerprint_sha256", ""),
                    "hassh": service.get("ssh", {}).get("hassh_fingerprint", ""),
                }

            case "HTTP":
                http_info = {
                    "html_tags": len(
                        service.get("http", {}).get("response", {}).get("html_tags", [])
                    ),
                    "html_title": len(
                        service.get("http", {})
                        .get("response", {})
                        .get("html_title", "")
                    ),
                }
                services[key] = http_info

    # Append services information to output
    output["services"] = services

    # Retrieve DNS values
    if host_data.get("dns"):
        for entry in host_data["dns"].get("reverse_dns", {}):
            output["dns"].add(entry)
        for entry in host_data["dns"].get("names", {}):
            output["dns"].add(entry)
    return output


def create_censys_context() -> CensysHosts:
    """Create a CensysHosts object to search with.

    Returns:
        CensysHosts: CensysHost object
    """
    if not (environ.get("CENSYS_API_ID") and environ.get("CENSYS_API_SECRET")):
        logging.error("No Censys API ID or API secret configured in env file.")

    return CensysHosts(environ.get("CENSYS_API_ID"), environ.get("CENSYS_API_SECRET"))
