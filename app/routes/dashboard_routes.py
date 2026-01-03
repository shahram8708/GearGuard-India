from __future__ import annotations

from collections import defaultdict
import csv
import io

from flask import Blueprint, render_template, request, Response, current_app
from flask_login import current_user, login_required
from sqlalchemy import func, case
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.models import (
    Equipment,
    MaintenanceRequest,
    MaintenanceStatus,
    MaintenanceTeam,
    RequestType,
    User,
    UserRole,
)
from app.tenant import tenant_query, tenant_required, role_required
from app.ai_service import ai_service


dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


def _status_counts(requests: list[MaintenanceRequest]) -> dict[MaintenanceStatus, int]:
    counts: dict[MaintenanceStatus, int] = defaultdict(int)
    for req in requests:
        counts[req.status] += 1
    return counts


def _type_counts(requests: list[MaintenanceRequest]) -> dict[RequestType, int]:
    counts: dict[RequestType, int] = defaultdict(int)
    for req in requests:
        counts[req.request_type] += 1
    return counts


@dashboard_bp.route("/", methods=["GET"])
@login_required
@tenant_required
def overview():
    org = current_user.organization
    users = tenant_query(User).all()
    equipments = tenant_query(Equipment).all()
    requests = tenant_query(MaintenanceRequest).order_by(MaintenanceRequest.updated_at.desc()).all()

    status_counts = _status_counts(requests)
    type_counts = _type_counts(requests)
    overdue_total = len([req for req in requests if req.is_overdue])

    admin_metrics = {
        "user_count": len(users),
        "equipment_count": len(equipments),
        "request_count": len(requests),
        "new": status_counts.get(MaintenanceStatus.NEW, 0),
        "in_progress": status_counts.get(MaintenanceStatus.IN_PROGRESS, 0),
        "repaired": status_counts.get(MaintenanceStatus.REPAIRED, 0),
        "scrap": status_counts.get(MaintenanceStatus.SCRAP, 0),
        "overdue": overdue_total,
        "preventive": type_counts.get(RequestType.PREVENTIVE, 0),
    }

    my_assigned = [req for req in requests if req.assigned_technician_id == current_user.id]
    my_requested = [req for req in requests if req.requested_by_id == current_user.id]
    my_open_assigned = [req for req in my_assigned if req.status in {MaintenanceStatus.NEW, MaintenanceStatus.IN_PROGRESS}]
    user_metrics = {
        "assigned_total": len(my_assigned),
        "open_assigned": len(my_open_assigned),
        "requested_total": len(my_requested),
    }

    status_labels = [
        "New",
        "In Progress",
        "Repaired",
        "Scrap",
    ]
    status_values = [
        status_counts.get(MaintenanceStatus.NEW, 0),
        status_counts.get(MaintenanceStatus.IN_PROGRESS, 0),
        status_counts.get(MaintenanceStatus.REPAIRED, 0),
        status_counts.get(MaintenanceStatus.SCRAP, 0),
    ]

    type_labels = ["Preventive", "Corrective"]
    type_values = [
        type_counts.get(RequestType.PREVENTIVE, 0),
        type_counts.get(RequestType.CORRECTIVE, 0),
    ]

    recent_requests = requests[:6]

    return render_template(
        "dashboard/overview.html",
        page_title="Dashboard",
        organization=org,
        admin_metrics=admin_metrics,
        user_metrics=user_metrics,
        equipments=equipments,
        requests=requests,
        recent_requests=recent_requests,
        is_admin=current_user.role == UserRole.ADMIN,
        status_labels=status_labels,
        status_values=status_values,
        type_labels=type_labels,
        type_values=type_values,
    )


def _period_bucket_expression():
    dialect = db.session.bind.dialect.name if db.session.bind else "sqlite"
    if dialect == "postgresql":
        return func.to_char(func.date_trunc("month", MaintenanceRequest.created_at), "YYYY-MM")
    if dialect in {"mysql", "mariadb"}:
        return func.date_format(MaintenanceRequest.created_at, "%Y-%m")
    return func.strftime("%Y-%m", MaintenanceRequest.created_at)


@dashboard_bp.route("/analytics", methods=["GET"])
@login_required
@tenant_required
def analytics():
    org = current_user.organization
    status_order = [
        MaintenanceStatus.NEW,
        MaintenanceStatus.IN_PROGRESS,
        MaintenanceStatus.REPAIRED,
        MaintenanceStatus.SCRAP,
    ]

    # Requests per team grouped by status
    team_rows = (
        db.session.query(
            func.coalesce(MaintenanceTeam.team_name, "Unassigned").label("team"),
            MaintenanceRequest.status,
            func.count(MaintenanceRequest.id),
        )
        .outerjoin(MaintenanceTeam, MaintenanceRequest.team_id == MaintenanceTeam.id)
        .filter(MaintenanceRequest.organization_id == org.id)
        .group_by("team", MaintenanceRequest.status)
        .order_by("team")
        .all()
    )

    team_labels = sorted({row.team for row in team_rows})
    team_status_matrix: dict[str, dict[MaintenanceStatus, int]] = {
        label: {status: 0 for status in status_order} for label in team_labels
    }
    for row in team_rows:
        team_status_matrix[row.team][row.status] = row[2]

    requests_per_team = {
        "labels": team_labels,
        "datasets": [
            {
                "label": "New",
                "data": [team_status_matrix[team][MaintenanceStatus.NEW] for team in team_labels],
                "backgroundColor": "#fbbf24",
            },
            {
                "label": "In Progress",
                "data": [team_status_matrix[team][MaintenanceStatus.IN_PROGRESS] for team in team_labels],
                "backgroundColor": "#4f46e5",
            },
            {
                "label": "Repaired",
                "data": [team_status_matrix[team][MaintenanceStatus.REPAIRED] for team in team_labels],
                "backgroundColor": "#22c55e",
            },
            {
                "label": "Scrap",
                "data": [team_status_matrix[team][MaintenanceStatus.SCRAP] for team in team_labels],
                "backgroundColor": "#0f172a",
            },
        ],
        "totals": {team: sum(team_status_matrix[team].values()) for team in team_labels},
    }

    # Requests per category
    category_rows = (
        db.session.query(
            func.coalesce(MaintenanceRequest.equipment_category_snapshot, Equipment.category, "Uncategorized").label(
                "category"
            ),
            func.count(MaintenanceRequest.id),
        )
        .outerjoin(Equipment, MaintenanceRequest.equipment_id == Equipment.id)
        .filter(MaintenanceRequest.organization_id == org.id)
        .group_by("category")
        .order_by(func.count(MaintenanceRequest.id).desc())
        .all()
    )
    category_labels = [row.category for row in category_rows]
    category_values = [row[1] for row in category_rows]
    requests_per_category = {
        "labels": category_labels,
        "values": category_values,
    }

    # Trend by month, grouped by request type
    period_expr = _period_bucket_expression()
    trend_rows = (
        db.session.query(
            period_expr.label("period"),
            MaintenanceRequest.request_type,
            func.count(MaintenanceRequest.id),
        )
        .filter(MaintenanceRequest.organization_id == org.id)
        .group_by("period", MaintenanceRequest.request_type)
        .order_by("period")
        .all()
    )
    periods = sorted({row.period for row in trend_rows})
    trend_map = {period: {RequestType.PREVENTIVE: 0, RequestType.CORRECTIVE: 0} for period in periods}
    for row in trend_rows:
        trend_map[row.period][row.request_type] = row[2]
    trend_chart = {
        "labels": periods,
        "preventive": [trend_map[p][RequestType.PREVENTIVE] for p in periods],
        "corrective": [trend_map[p][RequestType.CORRECTIVE] for p in periods],
    }

    # Performance / SLA style stats
    duration_stats = (
        db.session.query(
            func.avg(MaintenanceRequest.duration_hours),
            func.min(MaintenanceRequest.duration_hours),
            func.max(MaintenanceRequest.duration_hours),
        )
        .filter(
            MaintenanceRequest.organization_id == org.id,
            MaintenanceRequest.duration_hours.isnot(None),
            MaintenanceRequest.status == MaintenanceStatus.REPAIRED,
        )
        .one()
    )
    performance = {
        "avg_hours": round(duration_stats[0], 2) if duration_stats[0] else None,
        "fastest_hours": round(duration_stats[1], 2) if duration_stats[1] else None,
        "slowest_hours": round(duration_stats[2], 2) if duration_stats[2] else None,
    }

    completion_rows = (
        db.session.query(
            func.count(MaintenanceRequest.id),
            func.sum(
                case(
                    (MaintenanceRequest.status.in_([MaintenanceStatus.REPAIRED, MaintenanceStatus.SCRAP]), 1),
                    else_=0,
                )
            ),
        )
        .filter(MaintenanceRequest.organization_id == org.id)
        .one()
    )
    total_requests = completion_rows[0] or 0
    completed_requests = completion_rows[1] or 0
    completed_vs_pending = {
        "completed": completed_requests,
        "pending": max(total_requests - completed_requests, 0),
        "ratio": round(completed_requests / total_requests, 2) if total_requests else 0,
    }

    team_performance_rows = (
        db.session.query(
            func.coalesce(MaintenanceTeam.team_name, "Unassigned").label("team"),
            func.avg(MaintenanceRequest.duration_hours),
            func.count(MaintenanceRequest.id),
        )
        .outerjoin(MaintenanceTeam, MaintenanceRequest.team_id == MaintenanceTeam.id)
        .filter(
            MaintenanceRequest.organization_id == org.id,
            MaintenanceRequest.duration_hours.isnot(None),
            MaintenanceRequest.status == MaintenanceStatus.REPAIRED,
        )
        .group_by("team")
        .order_by(func.avg(MaintenanceRequest.duration_hours))
        .all()
    )
    team_performance = {
        "labels": [row.team for row in team_performance_rows],
        "avg_durations": [round(row[1], 2) if row[1] else 0 for row in team_performance_rows],
        "counts": [row[2] for row in team_performance_rows],
    }

    status_rows = (
        db.session.query(MaintenanceRequest.status, func.count(MaintenanceRequest.id))
        .filter(MaintenanceRequest.organization_id == org.id)
        .group_by(MaintenanceRequest.status)
        .all()
    )
    status_totals = {row.status.value: row[1] for row in status_rows}

    requests_by_category = dict(zip(category_labels, category_values))
    requests_by_team = {team: requests_per_team["totals"].get(team, 0) for team in team_labels}

    if request.args.get("export") == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Team", "Status", "Count"])
        for team in team_labels:
            for status in status_order:
                writer.writerow([team, status.value, team_status_matrix[team][status]])
        writer.writerow([])
        writer.writerow(["Category", "Count"])
        for category, count in zip(category_labels, category_values):
            writer.writerow([category, count])
        csv_response = Response(output.getvalue(), mimetype="text/csv")
        csv_response.headers["Content-Disposition"] = "attachment; filename=maintenance-analytics.csv"
        return csv_response

    return render_template(
        "dashboard/analytics.html",
        page_title="Analytics",
        organization=org,
        is_admin=current_user.role == UserRole.ADMIN,
        requests_per_team=requests_per_team,
        requests_per_category=requests_per_category,
        trend_chart=trend_chart,
        performance=performance,
        completed_vs_pending=completed_vs_pending,
        team_performance=team_performance,
        status_totals=status_totals,
        requests_by_category=requests_by_category,
        requests_by_team=requests_by_team,
        has_data=bool(total_requests),
    )


@dashboard_bp.route("/ai-insights", methods=["GET"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def ai_insights():
    org = current_user.organization

    equipment_rows = (
        db.session.query(
            Equipment.id,
            Equipment.name,
            Equipment.category,
            Equipment.status,
            func.count(MaintenanceRequest.id).label("requests"),
            func.sum(
                case(
                    (MaintenanceRequest.scheduled_date.isnot(None)
                     & (MaintenanceRequest.scheduled_date < func.current_date())
                     & MaintenanceRequest.status.notin_([MaintenanceStatus.REPAIRED, MaintenanceStatus.SCRAP]), 1),
                    else_=0,
                )
            ).label("overdue"),
        )
        .outerjoin(MaintenanceRequest, MaintenanceRequest.equipment_id == Equipment.id)
        .filter(Equipment.organization_id == org.id)
        .group_by(Equipment.id)
        .order_by(func.count(MaintenanceRequest.id).desc())
        .all()
    )

    recent_breakdowns = (
        tenant_query(MaintenanceRequest)
        .options(joinedload(MaintenanceRequest.equipment))
        .filter(MaintenanceRequest.request_type == RequestType.CORRECTIVE)
        .order_by(MaintenanceRequest.created_at.desc())
        .limit(30)
        .all()
    )

    summary = {
        "equipment": [
            {
                "id": row.id,
                "name": row.name,
                "category": row.category,
                "status": row.status.value,
                "request_count": int(row.requests or 0),
                "overdue_count": int(row.overdue or 0),
            }
            for row in equipment_rows
        ],
        "recent_breakdowns": [
            {
                "id": req.id,
                "equipment": req.equipment.name if req.equipment else None,
                "priority": req.priority,
                "status": req.status.value,
                "duration": req.duration_hours,
                "overdue": req.is_overdue,
            }
            for req in recent_breakdowns
        ],
    }

    ai_blocks: dict[str, list[str]] = {"top_risk": [], "likely_break": [], "efficiency": [], "ops": []}
    error_message = None
    try:
        ai_blocks = ai_service.ai_insights_panel(org.name, summary)
    except Exception as exc:  # pragma: no cover - runtime safety
        error_message = str(exc)
        current_app.logger.exception("AI insights generation failed")

    return render_template(
        "dashboard/ai_insights.html",
        page_title="AI Intelligence",
        organization=org,
        ai_blocks=ai_blocks,
        summary=summary,
        error_message=error_message,
    )
