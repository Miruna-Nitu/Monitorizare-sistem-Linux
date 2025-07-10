from Monitor import collect_system_metrics, monitor_app

data = collect_system_metrics()
print("CPU Usage:", data["cpu"])
print("Memory Usage:", data["mem"])
print("App 'sshd':", monitor_app("sshd"))

