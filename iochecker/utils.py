"""Utilities."""

import logging

DIFFERENCE_SCORES = {
    "SSH": 45,
    "HTTP": 5,
    "DNS": 5,
    "OS": 50,
    "C2_PORT": 40,
    "HTML_TAG": 10,
    "OPEN_PORT": 20,
}


def compare_fingerprints(
    first_fp: dict, second_fp: dict, c2_port: int | None = None, threshold: int = 50
) -> bool:
    """Compare two fingerprints.

    Args:
        first_fp (dict): first fingerprint
        second_fp (dict): second fingerprint
        c2_port (int | None, optional): port used by the C2 server. Defaults to None.
        threshold (int, optional): threshold for comparing fingerprints. Defaults to 50.

    Returns:
        bool: true if different, false otherwise
    """
    # First, check if both are empty
    if is_empty(first_fp) and is_empty(second_fp):
        logging.error("No fingerprints available for this IP address!")
        return False

    # Initialize the difference score
    differences_score = 0

    # Calculate the differences from first to second fingerprint
    differences_first_to_second = compare(first_fp, second_fp, set(), c2_port)

    # Than the other way around
    services_done = set(first_fp["services"].keys())
    differences_second_to_first = compare(
        first_fp=second_fp,
        second_fp=first_fp,
        services_done=services_done,
        c2_port=c2_port,
    )

    # Combine the differences
    differences_score = differences_first_to_second + differences_second_to_first

    logging.debug(f"Difference score: {differences_score}, threshold {threshold}")
    if differences_score > threshold:
        return True
    return False


def compare(
    first_fp: dict,
    second_fp: dict,
    services_done: set,
    c2_port: int | None = None,
) -> int:
    """Compare two fingerprints and calculate difference score.

    Args:
        first_fp (dict): first fingerprint
        second_fp (dict): second fingerprint
        services_done (set): set of services already compared. Defaults to set().
        c2_port (int | None, optional): port used by the C2 server. Defaults to None.

    Returns:
        int: difference score
    """
    diff_score = 0

    # Compare values that are always present
    if not services_done:
        # OS URI
        if first_fp["os"] != second_fp["os"]:
            diff_score += 1 * DIFFERENCE_SCORES["OS"]
            logging.debug(f"Different OS detected, difference: {diff_score}")

        # DNS entries
        diff_score += (
            len(
                first_fp.get("dns", set()).symmetric_difference(
                    second_fp.get("dns", set())
                )
            )
            * DIFFERENCE_SCORES["DNS"]
        )
        logging.debug(f"DNS entries processed, difference: {diff_score}")

        # Open ports, but first, remove the C2 port (as this would cause double counts)
        first_fp_open_ports = first_fp.get("open_ports", set())
        first_fp_open_ports.discard(c2_port)
        second_fp_open_ports = second_fp.get("open_ports", set())
        second_fp_open_ports.discard(c2_port)

        diff_score += (
            len(first_fp_open_ports.symmetric_difference(second_fp_open_ports))
            * DIFFERENCE_SCORES["OPEN_PORT"]
        )
        logging.debug(
            f"Ports {first_fp.get('open_ports', set())} were open on {first_fp['date']}, ports {second_fp.get('open_ports', set())} were open on {second_fp['date']}, difference: {diff_score}"
        )

        # C2 port
        if c2_port:
            if c2_port in second_fp.get(
                "open_ports", set()
            ) and c2_port not in second_fp.get("open_ports", set()):
                diff_score += 1 * DIFFERENCE_SCORES["C2_PORT"] - 10
                logging.debug(
                    f"C2 port {c2_port} was not open on {second_fp['date']}, difference: {diff_score}"
                )

    # Compare the services
    for item_key, item_data in first_fp["services"].items():
        # Retrieve port and service name
        port, service = item_key

        if item_key not in services_done:
            if item_key not in second_fp["services"].keys():
                diff_score += 1 * DIFFERENCE_SCORES[service]
                logging.debug(
                    f"{service} on port {port} was running on {first_fp['date']}, but not on {second_fp['date']}, difference: {diff_score}"
                )
                continue

            if item_data != second_fp["services"].get(item_key):
                diff_score += 1 * DIFFERENCE_SCORES[service]
                logging.debug(
                    f"{item_key} is different today! Was {item_data}, is now {second_fp['services'][item_key]}, difference: {diff_score}"
                )

    return diff_score


def is_empty(fp: dict) -> bool:
    """Test if dictionary of fingerprint is empty.

    Args:
        fp (dict): dictionary to check

    Returns:
        bool: true if empty, false otherwise
    """
    for feature in ["dns", "open_ports", "os", "services"]:
        if len(fp[feature]) > 0:
            return False
    return True
