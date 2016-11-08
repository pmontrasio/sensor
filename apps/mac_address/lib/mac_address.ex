defmodule MacAddress do
  def start_link(interface, period) do
    Task.start_link(fn -> count(interface, period) end)
  end

  def count(interface, period) do
    {:ok, pid} = :epcap.start([{:interface, interface, :monitor, true}])
    packet_monitor_loop(pid, %{}, :os.system_time(:millisecond) + period, period)
  end

  defp packet_monitor_loop(pid, addresses, send_at, period) do
    receive do
      {:packet, data_link_type, _, _, packet} ->

        addresses = case :pkt.decapsulate({:pkt.dlt(data_link_type), packet}) do

          [{:ether, source_mac_address, destination_mac_address, _, _}, _, _, _] ->
                update(addresses, source_mac_address, destination_mac_address)

          [{:ether, source_mac_address, destination_mac_address, _, _}, _, _] ->
                update(addresses, source_mac_address, destination_mac_address)

          _ -> addresses

        end
        now = :os.system_time(:millisecond)
        if now >= send_at do
          send_to_db(addresses)
          packet_monitor_loop(pid, %{}, now + period, period)
        else
          packet_monitor_loop(pid, addresses, send_at, period)
        end

      _ -> :epcap.stop(pid)
    end

  end

  defp update(addresses, source_mac_address, destination_mac_address) do
    source = Base.encode16(source_mac_address, case: :lower)
    destination = Base.encode16(destination_mac_address, case: :lower)
    addresses
    |> Map.update(source, 1, &(&1 + 1))
    |> Map.update(destination, 1, &(&1 + 1))
  end

  def send_to_db(addresses) do
    IO.puts("Send addresses: #{Enum.join(Map.keys(addresses, ", "))}")
  end

end

# Sample packets
# [{:ether, <<255, 255, 255, 255, 255, 255>>, <<156, 92, 249, 233, 22, 81>>, 2054, 0}, {:arp, 1, 2048, 6, 4, 1, <<156, 92, 249, 233, 22, 81>>, {192, 168, 1, 102}, <<0, 0, 0, 0, 0, 0>>, {192, 168, 1, 100}}, <<193, 172, 41, 253, 237, 24, 173, 65, 239, 155, 4, 178, 132, 0, 0, 0, 64, 107>>]

