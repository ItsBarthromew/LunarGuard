import psutil

class Statuses:

    @staticmethod
    def get_cpu_usage():
        return psutil.cpu_percent(interval=1)

    @staticmethod
    def get_memory_usage():
        memory = psutil.virtual_memory()
        return memory.percent

    @staticmethod
    def get_disk_usage():
        disk = psutil.disk_usage('/')
        return disk.percent

    @staticmethod
    def get_network_usage():
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv
        }
    

print(Statuses.get_cpu_usage())
print(Statuses.get_memory_usage())
print(Statuses.get_disk_usage())
print(Statuses.get_network_usage())  