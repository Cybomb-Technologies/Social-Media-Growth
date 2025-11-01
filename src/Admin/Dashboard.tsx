// src/Admin/Dashboard.tsx
import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
const API_URL = import.meta.env.VITE_API_URL;

// Define types for our data - Updated to match Order model
interface Order {
  _id: string;
  name: string;
  email: string;
  phone: string;
  service: string;
  serviceBudget: string;
  platform: string;
  timeline: string;
  goals: string;
  message: string;
  status: "pending" | "confirmed" | "in_progress" | "completed" | "cancelled";
  source: string;
  createdAt: string;
  updatedAt: string;
}

interface DashboardStats {
  totalOrders: number;
  pendingOrders: number;
  completedOrders: number;
  totalUsers: number;
  revenue: number;
}

interface StatData {
  value: string;
  label: string;
  change: string;
  icon: string;
  color: string;
}

interface Service {
  name: string;
  count: number;
  icon: string;
  platform: string;
}

interface ApiResponse<T> {
  success: boolean;
  data: T;
  pagination?: {
    current: number;
    total: number;
    results: number;
    totalResults: number;
  };
}

// User interface matching your Customer component
interface User {
  _id: string;
  name: string;
  email: string;
  phone: string;
  role: string;
  createdAt: string;
  status?: string;
}

// Define the display status type
type DisplayStatus = "pending" | "confirmed" | "in-progress" | "completed" | "cancelled";

const Dashboard = () => {
  const [orders, setOrders] = useState<Order[]>([]);
  const [recentOrders, setRecentOrders] = useState<Order[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [stats, setStats] = useState<DashboardStats>({
    totalOrders: 0,
    pendingOrders: 0,
    completedOrders: 0,
    totalUsers: 0,
    revenue: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch orders from backend
  const fetchOrders = async () => {
    try {
      const token = localStorage.getItem("token");
      const response = await fetch(`${API_URL}/api/orders?limit=100`, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        throw new Error("Failed to fetch orders");
      }

      const result: ApiResponse<Order[]> = await response.json();

      if (result.success) {
        setOrders(result.data);

        // Get the 8 most recent orders by sorting by createdAt date
        const sortedOrders = [...result.data].sort(
          (a, b) =>
            new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
        );
        setRecentOrders(sortedOrders.slice(0, 8));

        return result.data;
      } else {
        throw new Error("Failed to fetch data");
      }
    } catch (err) {
      console.error("Error fetching orders:", err);
      setError("Failed to load orders");
      return [];
    }
  };

  // Fetch users from backend - Similar to your Customer component
  const fetchUsers = async () => {
    try {
      const token = localStorage.getItem("token");
      const response = await fetch(`${API_URL}/api/auth`, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch users: ${response.statusText}`);
      }

      const result = await response.json();

      if (result.success) {
        setUsers(result.data);
        return result.data;
      } else {
        throw new Error(result.message || "Failed to load users");
      }
    } catch (err) {
      console.error("Error fetching users:", err);
      return [];
    }
  };

  // Calculate statistics from the data
  const calculateStats = (orders: Order[], users: User[]) => {
    const totalOrders = orders.length;
    const pendingOrders = orders.filter(
      (order) => order.status === "pending"
    ).length;
    const completedOrders = orders.filter(
      (order) => order.status === "completed"
    ).length;
    const totalUsers = users.length;

    // Calculate revenue from serviceBudget (extract numbers from strings like "$299/month")
    const revenue = orders.reduce((total, order) => {
      const priceMatch = order.serviceBudget.match(/\$(\d+)/);
      if (priceMatch) {
        return total + parseInt(priceMatch[1]);
      }
      return total;
    }, 0);

    return {
      totalOrders,
      pendingOrders,
      completedOrders,
      totalUsers,
      revenue,
    };
  };

  // Load all data
  const loadData = async () => {
    setLoading(true);
    setError(null);

    try {
      const [ordersData, usersData] = await Promise.all([
        fetchOrders(),
        fetchUsers(),
      ]);

      // Calculate stats from orders and users
      const calculatedStats = calculateStats(ordersData, usersData);
      setStats(calculatedStats);
    } catch (err) {
      setError("Failed to load dashboard data");
      console.error("Error loading dashboard data:", err);
    } finally {
      setLoading(false);
    }
  };

  // Initial data load
  useEffect(() => {
    loadData();
  }, []);

  // Refresh data function
  const refreshData = () => {
    loadData();
  };

  // Map order status to display status
  const getDisplayStatus = (status: Order["status"]): DisplayStatus => {
    const statusMap: Record<Order["status"], DisplayStatus> = {
      pending: "pending",
      confirmed: "confirmed",
      in_progress: "in-progress",
      completed: "completed",
      cancelled: "cancelled",
    };
    return statusMap[status] || "pending";
  };

  // Format date
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  };

  // Calculate popular services from actual order data
  const services: Service[] = orders
    .reduce((acc: Service[], order) => {
      const serviceName = order.service;
      const existingService = acc.find((s) => s.name === serviceName);

      if (existingService) {
        existingService.count += 1;
      } else {
        const serviceIcons: { [key: string]: string } = {
          "Follower Growth": "👥",
          "Engagement Boost": "💬",
          "Content Strategy": "📊",
          "Analytics & Insights": "📈",
          "Social Ads": "🎯",
          "Complete Management": "🚀",
          "Page Likes Growth": "👍",
          "Facebook Ads Management": "📱",
          "LinkedIn Ads": "💼",
          "Twitter Ads": "🐦",
          "YouTube Ads Management": "📺",
          "Subscriber Growth": "📹",
          "Video Optimization": "🎬",
        };

        acc.push({
          name: serviceName,
          count: 1,
          icon: serviceIcons[serviceName] || "🌟",
          platform: order.platform,
        });
      }

      return acc;
    }, [])
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  const statsData: StatData[] = [
    {
      value: stats.totalOrders.toString(),
      label: "Total Orders",
      change: "+12%",
      icon: "📦",
      color: "blue",
    },
    {
      value: stats.pendingOrders.toString(),
      label: "Pending Orders",
      change: "+3 new",
      icon: "⏳",
      color: "orange",
    },
    {
      value: stats.completedOrders.toString(),
      label: "Completed",
      change: "+8%",
      icon: "✅",
      color: "green",
    },
    // {
    //   value: `$${stats.revenue}`,
    //   label: "Total Revenue",
    //   change: "+15%",
    //   icon: "💰",
    //   color: "purple",
    // },
  ];

  const getStatusColor = (status: DisplayStatus): string => {
    const colors: Record<DisplayStatus, string> = {
      pending: "#f59e0b",
      confirmed: "#3b82f6",
      "in-progress": "#8b5cf6",
      completed: "#10b981",
      cancelled: "#ef4444",
    };
    return colors[status] || "#6b7280";
  };

  const styles = {
    dashboardContainer: {
      padding: "2rem",
      maxWidth: "1400px",
      margin: "0 auto",
      marginLeft: "0px",
      transition: "margin-left 0.3s ease",
    },
    loadingContainer: {
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
      padding: "4rem",
      flexDirection: "column" as const,
      gap: "1rem",
    },
    errorContainer: {
      background: "#fee2e2",
      border: "1px solid #fecaca",
      color: "#dc2626",
      padding: "1rem",
      borderRadius: "8px",
      marginBottom: "1rem",
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
    },
    retryButton: {
      background: "#dc2626",
      color: "white",
      border: "none",
      padding: "0.5rem 1rem",
      borderRadius: "6px",
      cursor: "pointer",
      fontWeight: "600",
    },
    dashboardHeader: {
      display: "flex",
      justifyContent: "space-between",
      alignItems: "flex-start",
      marginBottom: "2rem",
      flexWrap: "wrap" as const,
      gap: "1rem",
    },
    dashboardTitle: {
      fontSize: "2rem",
      fontWeight: "700",
      color: "#1a202c",
      marginBottom: "0.5rem",
    },
    dashboardSubtitle: {
      color: "#718096",
      fontSize: "1.1rem",
    },
    headerActions: {
      display: "flex",
      gap: "1rem",
      flexWrap: "wrap" as const,
    },
    btnPrimary: {
      background: "#4f46e5",
      color: "white",
      border: "none",
      padding: "0.75rem 1.5rem",
      borderRadius: "10px",
      fontWeight: "600",
      cursor: "pointer",
      transition: "all 0.3s ease",
      display: "flex",
      alignItems: "center",
      gap: "0.5rem",
    },
    btnSecondary: {
      background: "white",
      color: "#4a5568",
      border: "1px solid #e2e8f0",
      padding: "0.75rem 1.5rem",
      borderRadius: "10px",
      fontWeight: "600",
      cursor: "pointer",
      transition: "all 0.3s ease",
      display: "flex",
      alignItems: "center",
      gap: "0.5rem",
    },
    statsGrid: {
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
      gap: "1.5rem",
      marginBottom: "2rem",
    },
    statCard: {
      background: "white",
      padding: "1.5rem",
      borderRadius: "16px",
      boxShadow: "0 4px 6px rgba(0, 0, 0, 0.05)",
      border: "1px solid #e2e8f0",
      transition: "all 0.3s ease",
    },
    statContent: {
      display: "flex",
      justifyContent: "space-between",
      alignItems: "flex-start",
      marginBottom: "1rem",
    },
    statLabel: {
      fontSize: "0.875rem",
      fontWeight: "600",
      color: "#718096",
      marginBottom: "0.5rem",
      textTransform: "uppercase" as const,
      letterSpacing: "0.05em",
    },
    statValue: {
      fontSize: "2rem",
      fontWeight: "700",
      marginBottom: "0.25rem",
    },
    statChange: {
      fontSize: "0.875rem",
      fontWeight: "600",
    },
    statChangePositive: {
      color: "#10b981",
    },
    statIcon: {
      fontSize: "2.5rem",
      opacity: 0.8,
    },
    dashboardContent: {
      display: "grid",
      gridTemplateColumns: "2fr 1fr",
      gap: "2rem",
      marginBottom: "2rem",
    },
    contentCard: {
      background: "white",
      borderRadius: "16px",
      boxShadow: "0 4px 6px rgba(0, 0, 0, 0.05)",
      border: "1px solid #e2e8f0",
      overflow: "hidden",
    },
    cardHeader: {
      padding: "1.5rem",
      borderBottom: "1px solid #e2e8f0",
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
    },
    cardTitle: {
      fontSize: "1.25rem",
      fontWeight: "600",
      color: "#1a202c",
    },
    textLink: {
      color: "#4f46e5",
      textDecoration: "none",
      fontWeight: "500",
      cursor: "pointer",
      background: "none",
      border: "none",
      fontSize: "0.875rem",
    },
    table: {
      width: "100%",
      borderCollapse: "collapse" as const,
    },
    tableHeader: {
      background: "#f8fafc",
      borderBottom: "1px solid #e2e8f0",
    },
    tableHeaderCell: {
      padding: "1rem",
      textAlign: "left" as const,
      fontWeight: "600",
      color: "#374151",
      fontSize: "0.875rem",
    },
    tableCell: {
      padding: "1rem",
      borderBottom: "1px solid #f1f5f9",
    },
    statusBadge: {
      padding: "0.25rem 0.75rem",
      borderRadius: "12px",
      fontSize: "0.75rem",
      fontWeight: "600",
      display: "inline-block",
    },
    servicesGrid: {
      padding: "1.5rem",
      display: "grid",
      gap: "1rem",
    },
    serviceItem: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "1rem",
      background: "#f8fafc",
      borderRadius: "12px",
      transition: "all 0.3s ease",
    },
    serviceInfo: {
      display: "flex",
      alignItems: "center",
      gap: "1rem",
    },
    serviceIcon: {
      fontSize: "1.5rem",
    },
    serviceName: {
      fontWeight: "500",
      color: "#374151",
    },
    servicePlatform: {
      fontSize: "0.75rem",
      color: "#6b7280",
      background: "#e5e7eb",
      padding: "0.2rem 0.5rem",
      borderRadius: "6px",
    },
    serviceCount: {
      background: "#4f46e5",
      color: "white",
      padding: "0.25rem 0.75rem",
      borderRadius: "12px",
      fontSize: "0.875rem",
      fontWeight: "600",
    },
    quickActionsGrid: {
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
      gap: "1rem",
      marginTop: "2rem",
    },
    quickActionBtn: {
      background: "white",
      border: "1px solid #e2e8f0",
      borderRadius: "12px",
      padding: "1.5rem 1rem",
      cursor: "pointer",
      transition: "all 0.3s ease",
      display: "flex",
      flexDirection: "column" as const,
      alignItems: "center",
      gap: "0.5rem",
      fontWeight: "500",
      color: "#374151",
    },
    actionIcon: {
      fontSize: "2rem",
    },
    emptyState: {
      padding: "2rem",
      textAlign: "center" as const,
      color: "#6b7280",
    },
    "@media (max-width: 1024px)": {
      dashboardContent: {
        gridTemplateColumns: "1fr",
      },
      dashboardContainer: {
        marginLeft: "0",
        padding: "1rem",
      },
    },
    "@media (max-width: 768px)": {
      statsGrid: {
        gridTemplateColumns: "1fr",
      },
      headerActions: {
        width: "100%",
        justifyContent: "center",
      },
      dashboardHeader: {
        flexDirection: "column",
        alignItems: "center",
        textAlign: "center" as const,
      },
      quickActionsGrid: {
        gridTemplateColumns: "1fr",
      },
    },
  };

  const getColorStyle = (color: string) => {
    const colors: { [key: string]: any } = {
      blue: { color: "#3b82f6" },
      green: { color: "#10b981" },
      purple: { color: "#8b5cf6" },
      orange: { color: "#f59e0b" },
    };
    return colors[color] || colors.blue;
  };

  if (loading) {
    return (
      <div style={styles.dashboardContainer}>
        <div style={styles.loadingContainer}>
          <div>Loading dashboard data...</div>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.dashboardContainer}>
      {error && (
        <div style={styles.errorContainer}>
          <span>{error}</span>
          <button style={styles.retryButton} onClick={refreshData}>
            Retry
          </button>
        </div>
      )}

      <div style={styles.dashboardHeader}>
        <div>
          <h1 style={styles.dashboardTitle}>Order Dashboard</h1>
          <p style={styles.dashboardSubtitle}>
            Manage customer orders and service requests
          </p>
        </div>
        <div style={styles.headerActions}>
          <button
            style={styles.btnSecondary}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "#f7fafc";
              e.currentTarget.style.borderColor = "#cbd5e0";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "white";
              e.currentTarget.style.borderColor = "#e2e8f0";
            }}
            onClick={refreshData}
          >
            <span>↻</span>
            Refresh Data
          </button>
          <Link to="/admin/orders" style={{ textDecoration: 'none' }}>
            <button
              style={styles.btnPrimary}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "#4338ca";
                e.currentTarget.style.transform = "translateY(-2px)";
                e.currentTarget.style.boxShadow =
                  "0 4px 12px rgba(79, 70, 229, 0.3)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "#4f46e5";
                e.currentTarget.style.transform = "translateY(0)";
                e.currentTarget.style.boxShadow = "none";
              }}
            >
              <span>+</span>
              View All Orders
            </button>
          </Link>
        </div>
      </div>

      <div style={styles.statsGrid}>
        {statsData.map((stat, index) => (
          <div
            key={index}
            style={styles.statCard}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = "translateY(-4px)";
              e.currentTarget.style.boxShadow = "0 8px 25px rgba(0, 0, 0, 0.1)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = "translateY(0)";
              e.currentTarget.style.boxShadow = "0 4px 6px rgba(0, 0, 0, 0.05)";
            }}
          >
            <div style={styles.statContent}>
              <div>
                <h3 style={styles.statLabel}>{stat.label}</h3>
                <p
                  style={{ ...styles.statValue, ...getColorStyle(stat.color) }}
                >
                  {stat.value}
                </p>
                {/* <span
                  style={{ ...styles.statChange, ...styles.statChangePositive }}
                >
                  {stat.change}
                </span> */}
              </div>
              <div style={styles.statIcon}>{stat.icon}</div>
            </div>
          </div>
        ))}
      </div>

      <div style={styles.dashboardContent}>
        <div style={styles.contentCard}>
          <div style={styles.cardHeader}>
            <h2 style={styles.cardTitle}>Recent Orders</h2>
            <Link to="/admin/orders">
              <button style={styles.textLink}>View All</button>
            </Link>
          </div>
          {recentOrders.length === 0 ? (
            <div style={styles.emptyState}>No orders found</div>
          ) : (
            <table style={styles.table}>
              <thead style={styles.tableHeader}>
                <tr>
                  <th style={styles.tableHeaderCell}>Customer</th>
                  <th style={styles.tableHeaderCell}>Service</th>
                  <th style={styles.tableHeaderCell}>Platform</th>
                  <th style={styles.tableHeaderCell}>Status</th>
                  <th style={styles.tableHeaderCell}>Date</th>
                </tr>
              </thead>
              <tbody>
                {recentOrders.map((order) => {
                  const displayStatus = getDisplayStatus(order.status);
                  return (
                    <tr key={order._id}>
                      <td style={styles.tableCell}>
                        <div>
                          <div style={{ fontWeight: "600" }}>{order.name}</div>
                          <div style={{ fontSize: "0.875rem", color: "#6b7280" }}>
                            {order.email}
                          </div>
                        </div>
                      </td>
                      <td style={styles.tableCell}>{order.service}</td>
                      <td style={styles.tableCell}>{order.platform}</td>
                      <td style={styles.tableCell}>
                        <span
                          style={{
                            ...styles.statusBadge,
                            background: getStatusColor(displayStatus) + "20",
                            color: getStatusColor(displayStatus),
                          }}
                        >
                          {displayStatus.charAt(0).toUpperCase() +
                            displayStatus.slice(1)}
                        </span>
                      </td>
                      <td style={styles.tableCell}>
                        {formatDate(order.createdAt)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        <div style={styles.contentCard}>
          <div style={styles.cardHeader}>
            <h2 style={styles.cardTitle}>Popular Services</h2>
          </div>
          <div style={styles.servicesGrid}>
            {services.map((service, index) => (
              <div
                key={index}
                style={styles.serviceItem}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "#4f46e5";
                  e.currentTarget.style.transform = "translateX(4px)";
                  const name = e.currentTarget.querySelector(
                    ".service-name"
                  ) as HTMLElement;
                  const platform = e.currentTarget.querySelector(
                    ".service-platform"
                  ) as HTMLElement;
                  const count = e.currentTarget.querySelector(
                    ".service-count"
                  ) as HTMLElement;
                  if (name && platform && count) {
                    name.style.color = "white";
                    platform.style.background = "white";
                    platform.style.color = "#4f46e5";
                    count.style.background = "white";
                    count.style.color = "#4f46e5";
                  }
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "#f8fafc";
                  e.currentTarget.style.transform = "translateX(0)";
                  const name = e.currentTarget.querySelector(
                    ".service-name"
                  ) as HTMLElement;
                  const platform = e.currentTarget.querySelector(
                    ".service-platform"
                  ) as HTMLElement;
                  const count = e.currentTarget.querySelector(
                    ".service-count"
                  ) as HTMLElement;
                  if (name && platform && count) {
                    name.style.color = "#374151";
                    platform.style.background = "#e5e7eb";
                    platform.style.color = "#6b7280";
                    count.style.background = "#4f46e5";
                    count.style.color = "white";
                  }
                }}
              >
                <div style={styles.serviceInfo}>
                  <span style={styles.serviceIcon}>{service.icon}</span>
                  <div>
                    <div style={styles.serviceName} className="service-name">
                      {service.name}
                    </div>
                    <span style={styles.servicePlatform} className="service-platform">
                      {service.platform}
                    </span>
                  </div>
                </div>
                <span style={styles.serviceCount} className="service-count">
                  {service.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;