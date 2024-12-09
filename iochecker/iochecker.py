"""Main program file for IoChecker."""

import datetime
import logging
import sys
from argparse import ArgumentParser, Namespace
from datetime import date
from ipaddress import ip_address

import get_censys_data as cen
import get_shodan_data as sho
import utils
from dotenv import load_dotenv


def main(args: Namespace) -> None:
    """Execute the main functionality.

    Args:
        args (Namespace): namespace with arguments
    """
    # Initialize logging facilities
    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    logging.info(
        f"Providing context with {args.source} for IoC {args.ip}{':' + str(args.port) if args.port else ''}, known malicious on {args.date_arrived}"
    )

    # Select source for IoC enrichment
    match args.source:
        case "censys":
            # First, obtain the data for the timestamp given
            ip_data_date_arrived = cen.get_ip_information(args.ip, args.date_arrived)
            fingerprint_date_arrived = cen.extract_relevant_data(
                ip_data_date_arrived, args.date_arrived
            )

            # Check if malicious port is in the set of open ports, warn the user if not
            if args.port:
                if args.port not in fingerprint_date_arrived.get("open_ports", {}):
                    logging.warning(
                        f"Port {args.port} not open on first seen date, this may lead to inaccurate results!"
                    )

            # Then, obtain the data for today
            ip_data_today = cen.get_ip_information(args.ip, date.today())
            fingerprint_today = cen.extract_relevant_data(ip_data_today, date.today())

            # If both timestamps have a valid fingerprint
            if ip_data_date_arrived and ip_data_today:

                # Compare the two fingerprints to see if the IP is still relevant
                fingerprint_difference = utils.compare_fingerprints(
                    fingerprint_date_arrived,
                    fingerprint_today,
                    args.port if args.port else None,
                )
            else:
                logging.error(
                    "No information in Censys available for this IP, aborting"
                )
                sys.exit(1)

        case "shodan":
            # First, obtain the data for the timestamp given
            ip_data_total = sho.get_ip_information(args.ip)
            if ip_data_total:
                fingerprint_date_arrived = sho.extract_relevant_data(
                    ip_data_total, args.date_arrived
                )

                # Check if malicious port is in the set of open ports, warn the user if not
                if args.port:
                    if args.port not in fingerprint_date_arrived.get("open_ports", {}):
                        logging.warning(
                            f"Port {args.port} not open on first seen date, this may lead to inaccurate results!"
                        )

                # Than, obtain the data for today
                fingerprint_today = sho.extract_relevant_data(
                    ip_data_total, date.today()
                )

                # Compare the two to see if still relevant
                fingerprint_difference = utils.compare_fingerprints(
                    fingerprint_date_arrived, fingerprint_today
                )
            else:
                logging.error(
                    "No information available in Shodan for this IP address, aborting"
                )
                sys.exit(1)
        case _:
            logging.error("Unsupported source selected")

    # If significantly different, log output and exit 1
    if fingerprint_difference:
        logging.info(f"IoC {args.ip} has changed significantly, not valid anymore.")
        sys.exit(1)

    # If not significantly different, log output and exit 0
    logging.info(f"IoC {args.ip} is still valid")
    sys.exit(0)


if __name__ == "__main__":
    parser = ArgumentParser(
        description="IoChecker -- Provide more context for your IoCs"
    )
    parser.add_argument("ip", help="Specify the IP address to lookup", type=ip_address)
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="Specify the port for the malicious activity on this IP",
    )
    parser.add_argument(
        "-d",
        "--date_arrived",
        type=datetime.date.fromisoformat,
        default=date.today(),
        help="Specify the date this IoC was listed as malicious (YYYY-MM-DD)",
    )
    parser.add_argument(
        "-s",
        "--source",
        type=str,
        default="censys",
        choices=["shodan", "censys"],
        help="Specify the datasource to use, either Shodan or Censys",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        default=False,
        action="store_true",
        help="Enable verbose logging",
    )

    # Parse all command line arguments
    arguments = parser.parse_args()
    arguments.ip = str(arguments.ip)
    load_dotenv()

    # Execute the main program
    main(arguments)
