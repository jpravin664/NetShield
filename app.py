import streamlit as st
from scanner import scan_ports
import time  # For simulating scan progress

# Background video CSS and HTML
background_video = """
<style>
video#bgvid {
    position: fixed;
    top: 50%;
    left: 60%;
    width: 90%;
    height: 120%; 
    z-index: -1;
    transform: translate(-50%, -50%);
    background-size: cover;
    overflow: hidden;
}
.stApp {
    background: rgba(0, 0, 0, 0.5); /* Transparent overlay to improve readability */
    color: white;
    z-index: 1;
}
.translucent-box {
    background: rgba(0, 0, 0, 0.6); /* Translucent dark background */
    padding: 20px;
    border-radius: 15px;
    width: 80%;
    margin: auto;
    text-align: center;
    color: white;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
}
</style>

<video autoplay muted loop id="bgvid">
    <source src="https://cdn.pixabay.com/video/2015/11/02/1236-144355017_large.mp4">

</video>
"""

# Inject the background video HTML into the Streamlit app
st.markdown(background_video, unsafe_allow_html=True)

# Translucent box for text and results
st.markdown("""
<div class="translucent-box">
    <h1>Network Vulnerability Scanner</h1>
    <p>Welcome to the Network Vulnerability Scanner. Use the options on the sidebar to begin scanning.</p>
</div>
""", unsafe_allow_html=True)

# Input Form in Sidebar
st.sidebar.header("Scan Options")
target = st.sidebar.text_input("Enter Target IP or Domain (e.g. 192.168.1.1, example.com)")

# Enhanced buttons for scan options
scan_option = st.sidebar.radio(
    "Select Scan Type",
    ["Normal Scan", "Quick Scan", "Full Scan", "Vulnerability Scan"]
)

# Progress bar
progress_bar = st.sidebar.progress(0)

# Disable button during scanning
scan_button = st.sidebar.button("Start Scan")

# Mapping scan types to internal scanner modes
scan_type_map = {
    "Normal Scan": "normal",
    "Quick Scan": "quick",
    "Full Scan": "full"
}
# Start scan when button is pressed
if scan_button:
    vulnerabilities = {}  # Initialize vulnerabilities here
    open_ports = {}  # Initialize open_ports to avoid undefined reference
    
    if target:
        # Display the selected scan type and target in a translucent box
        st.markdown("""<div class="translucent-box">""", unsafe_allow_html=True)
        st.write(f"### Scanning target: `{target}` using `{scan_option}`...")

        try:
            # Perform Vulnerability Scan
            if scan_option == "Vulnerability Scan":
                st.write("Performing Vulnerability Scan using NSE scripts...")
                progress_bar.progress(20)
                
                # Start vulnerability scan
                open_ports = scan_ports(target, scan_type="vuln")
                progress_bar.progress(60)  # Update progress

                st.markdown(f"## Vulnerability Check Results")
                for host, ports in open_ports.items():
                    st.markdown(f"### Host: `{host}`")
                    if ports:
                        for port_info in ports:
                            # Expander for each port to make details collapsible
                            with st.expander(f"Port {port_info['port']} ({port_info['service']}) is open"):
                                st.write(f"Port {port_info['port']} is open with service `{port_info['service']}`")

                                # If vulnerabilities exist, display them
                                if 'vulns' in port_info:
                                    for vuln in port_info['vulns']:
                                        vuln_name = list(vuln.keys())[0]
                                        st.markdown(f"**Vulnerability:** `{vuln_name}`")
                                else:
                                    st.write("No vulnerabilities detected.")
                    else:
                        st.markdown("No open ports detected.")
                
                progress_bar.progress(100)

            else:
                # Perform Port Scan (Normal, Quick, Full)
                st.write(f"Performing {scan_option}...")
                progress_bar.progress(10)  # Update progress
                open_ports = scan_ports(target, scan_type=scan_type_map[scan_option])
                progress_bar.progress(50)  # Update progress

                st.markdown(f"## Open Ports on `{target}`")
                for host, ports in open_ports.items():
                    st.markdown(f"### Host: `{host}`")
                    for port_info in ports:
                        st.markdown(f"- **Port {port_info['port']}** ({port_info['service']}) is open")

                progress_bar.progress(100)  # Complete scan

            # Option to download results (both open ports and vulnerabilities)
            if open_ports or vulnerabilities:  # Check if results are available
                combined_results = {
                    "open_ports": open_ports,
                    "vulnerabilities": vulnerabilities
                }
                st.sidebar.download_button(
                    "Download Scan Results",
                    data=str(combined_results).encode(),
                    file_name="scan_results.txt",
                    mime="text/plain"
                )

        except Exception as e:
            st.error(f"An error occurred: {e}")

        # Close the translucent box after scan results
        st.markdown("</div>", unsafe_allow_html=True)

        # Reset progress bar after scan is done
        progress_bar.empty()

    else:
        st.error("Please enter a valid IP address or domain.")
